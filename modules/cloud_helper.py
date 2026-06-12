def is_s3_bucket_url(url: str) -> bool:
    return ".s3." in url or url.startswith("s3://")

