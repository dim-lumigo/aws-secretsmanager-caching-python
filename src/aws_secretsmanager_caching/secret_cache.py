# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""High level AWS Secrets Manager caching client."""
from copy import deepcopy

import botocore.session
from pkg_resources import DistributionNotFound, get_distribution

from .cache import LRUCache, SecretCacheItem
from .config import SecretCacheConfig


class SecretCache:
    """Secret Cache client for AWS Secrets Manager secrets"""

    try:
        __version__ = get_distribution('aws_secretsmanager_caching').version
    except DistributionNotFound:
        __version__ = '0.0.0'

    def __init__(self, config=SecretCacheConfig(), client=None):
        """Construct a secret cache using the given configuration and
        AWS Secrets Manager boto client.

        :type config: aws_secretsmanager_caching.SecretCacheConfig
        :param config: Secret cache configuration

        :type client: botocore.client.BaseClient
        :param client: botocore 'secretsmanager' client
        """
        self._client = client
        self._config = deepcopy(config)
        self._cache = LRUCache(max_size=self._config.max_cache_size)
        if self._client is None:
            self._client = botocore.session.get_session().create_client("secretsmanager")

        self._client.meta.config.user_agent_extra = "AwsSecretCache/{}".format(SecretCache.__version__)

    def _get_cached_secret(self, secret_id):
        """Get a cached secret for the given secret identifier.

        :type secret_id: str
        :param secret_id: The secret identifier

        :rtype: aws_secretsmanager_caching.cache.SecretCacheItem
        :return: The associated cached secret item
        """
        secret = self._cache.get(secret_id)
        if secret is not None:
            return secret
        self._cache.put_if_absent(
            secret_id, SecretCacheItem(config=self._config, client=self._client, secret_id=secret_id)
        )
        return self._cache.get(secret_id)

    def get_secret_string(self, secret_id, version_stage=None):
        """Get the secret string value from the cache.

        :type secret_id: str
        :param secret_id: The secret identifier

        :type version_stage: str
        :param version_stage: The stage for the requested version.

        :rtype: str
        :return: The associated secret string value
        """
        secret = self._get_cached_secret(secret_id).get_secret_value(version_stage)
        if secret is None:
            return secret
        return secret.get("SecretString")

    def get_secret_binary(self, secret_id, version_stage=None):
        """Get the secret binary value from the cache.

        :type secret_id: str
        :param secret_id: The secret identifier

        :type version_stage: str
        :param version_stage: The stage for the requested version.

        :rtype: bytes
        :return: The associated secret binary value
        """
        secret = self._get_cached_secret(secret_id).get_secret_value(version_stage)
        if secret is None:
            return secret
        return secret.get("SecretBinary")


def assume_account_role(account_id, role_name, duration = 900):
    """Temporary assume cross-account role.

    :type account_id: str
    :param account_id: Account ID for delegating

    :type role_name: str
    :param role_name: Role name to assume

    :type duration: int
    :param duration: Assumed role session duration (seconds)

    :rtype: botocore.session.Session
    :return: botocore session object
    """
    sts = botocore.session.get_session().create_client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    session_name = "SecretCacheSession"
    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        DurationSeconds=duration
        )
    session = botocore.session.Session()
    session.set_credentials(
        access_key=response["Credentials"]["AccessKeyId"],
        secret_key=response["Credentials"]["SecretAccessKey"],
        token=response["Credentials"]["SessionToken"]
        )
    return session


def get_crossaccount_clients(account_id, role_name, regions, duration=900):
    """Return AWS SecretsManager clients for crossaccount access for multiple regions.

    :type account_id: str
    :param account_id: Account ID for delegating

    :type role_name: str
    :param role_name: Role name to assume

    :type duration: int
    :param duration: Assumed role session duration (seconds)

    :rtype: List[botocore.client.BaseClient]
    :return: List of botocore BaseClient clients
    """
    session = assume_account_role(account_id, role_name, duration)
    return [session.create_client("secretsmanager", region) for region in regions]


def get_multiregion_caches(clients):
    """Return secret caches for multiple regions.

    :type clients: List[botocore.client.BaseClient]
    :param account_id: List of botocore BaseClient objects

    :rtype: List[aws_secretsmanager_caching.SecretCache]
    :return: List of SecretCache caches
    """
    return [SecretCache(client=client) for client in clients]
