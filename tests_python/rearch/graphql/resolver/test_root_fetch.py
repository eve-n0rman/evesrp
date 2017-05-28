import uuid

from graphql_relay.node.node import to_global_id
import pytest


@pytest.mark.parametrize(
    'provider_uuid,key,type_name,entity_id',
    (
        (uuid.UUID('3a80f9c8-f552-472b-9ed4-a479cb8f8521'),
         'authn_user',
         'User',
         9),
        (uuid.UUID('3a80f9c8-f552-472b-9ed4-a479cb8f8521'),
         'authn_group',
         'Group',
         3000),
    ),
    ids=('user', 'group')
)
def test_identity(graphql_client, provider_uuid, key, type_name, entity_id):
    query_placeholders = {}
    field_name = type_name.lower()
    query_placeholders['type_name'] = type_name
    query_placeholders['field_name'] = field_name
    query = '''
    query getIdentity($uuid: ID!, $key: ID!) {
        identity(uuid: $uuid, key: $key) {
            ... on %(type_name)sIdentity {
                providerUuid
                providerKey
                %(field_name)s {
                    id
                }
            }
        }
    }
    ''' % query_placeholders
    result = graphql_client.execute(
        query,
        variable_values={
            'uuid': str(provider_uuid),
            'key': key,
        }
    )
    entity = {'id': to_global_id(type_name, entity_id)}
    assert result == {
        'data': {
            'identity': {
                'providerUuid': str(provider_uuid),
                'providerKey': key,
                field_name: entity,
            }
        }
    }



@pytest.mark.parametrize(
    'group_id,expected_user_ids',
    (
        (None, (9, 2, 7)),
        (to_global_id('Group', 3000), (9, )),
        (to_global_id('Group', 5000), (2, 9)),
    ),
    ids=('all_users', 'one_user', 'multiple_users')
)
def test_users(graphql_client, group_id, expected_user_ids):
    query = '''
    query getUsers($groupID: ID) {
        users(groupId: $groupID) {
            id
        }
    }
    '''
    result = graphql_client.execute(query,
                                    variable_values={'groupID': group_id})
    assert 'data' in result
    ids = {user['id'] for user in result['data']['users']}
    expected_relay_ids = {to_global_id('User', uid) for uid in
                          expected_user_ids}
    assert ids == expected_relay_ids
