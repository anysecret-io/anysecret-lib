# AnySecret.io - Universal Secret & Configuration Management

[![PyPI version](https://badge.fury.io/py/anysecret-io.svg)](https://badge.fury.io/py/anysecret-io)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

One CLI. One SDK. All your cloud providers.

## Installation

```bash
pip install anysecret-io
```

## Quick Start

```python
import anysecret

# Automatically routes to the right provider (AWS, GCP, Azure, K8s, etc.)
db_password = anysecret.get('db_password')
api_timeout = anysecret.get('api_timeout')
```

## Documentation

Full documentation available at [anysecret.io](https://anysecret.io)

## License

- **Open Source**: AGPL-3.0 for personal and open source use
- **Commercial**: Commercial license available for proprietary use
- **SaaS**: Special licensing for SaaS platforms

See [anysecret.io/license](https://anysecret.io/license) for details.

