def parse_otp_credential_data(data: str) -> tuple[str, str]:
    lines = [line.strip() for line in data.splitlines() if not line.isspace()]
    secret = lines.pop(0)

    for line in lines:
        if line.lower().startswith(("name:", "username:")):
            name = line.split(":")[-1].strip()
    else:
        name = lines[0]

    return name, secret
