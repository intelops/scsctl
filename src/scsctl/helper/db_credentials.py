
import hvac

def get_credentials_from_hashicorp_vault(url: str, token: str, path: str):
    client = hvac.Client(
        url=url,
        token=token,
    )

    read_response = client.secrets.kv.read_secret_version(path=path)

    data = read_response['data']['data']

    return data