"""
demo_app.py — small sample app for GitHub Secret Protection demos.

HOW TO USE
1. git checkout -b secret-protection-demo
2. Edit ONLY the line marked <<< SWAP THIS LINE >>> below.
   Safe value to paste in (no live credential needed):
     AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
   (This is AWS's own public, non-functional example key — safe to use,
   recognized by GitHub's push protection.)
3. git add demo_app.py && git commit -m "Add config" && git push
   -> push should be BLOCKED with inline remediation.
4. Swap the line back to the placeholder, amend the commit, push again
   -> push succeeds, showing the "fixed" happy path.
5. After the demo, confirm no real value was left in git history.
"""

import os


class Config:
    ENVIRONMENT = "demo"
    DATABASE_URL = "postgres://demo_user:placeholder@localhost:5432/demo_db"

    # <<< SWAP THIS LINE >>>
    AWS_ACCESS_KEY_ID = "11ALL37PA0NICv1Nnd4wxo_dyNslty3VM7SNleAXP7XwvByc99811QSZh4iw7FHttaPkZC5L5V6ZLHM112wss"

    LOG_LEVEL = "debug"
    FEATURE_FLAG_NEW_UI = True


def get_s3_client_config():
    """Pretend helper that would normally build an S3 client config."""
    return {
        "access_key_id": Config.AWS_ACCESS_KEY_ID,
        "region": "eu-west-1",
    }


def main():
    print(f"Starting demo app in {Config.ENVIRONMENT} mode...")
    print(f"DB target: {Config.DATABASE_URL}")
    print("S3 client config:", get_s3_client_config())


if __name__ == "__main__":
    main()