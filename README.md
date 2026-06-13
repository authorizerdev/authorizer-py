# authorizer-python

Python SDK for [authorizer.dev](https://authorizer.dev) — self-hosted authentication & authorization.

## Installation

```bash
pip install authorizer-dev
```

## Usage

```python
from authorizer import AuthorizerClient

client = AuthorizerClient(
    client_id="your-client-id",
    authorizer_url="https://your-authorizer-instance.com",
)
```

## License

Apache-2.0
