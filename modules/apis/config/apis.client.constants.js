'use strict';

//Setting up route
angular.module('apis').constant('PLUGINSAVAILABLE', [
	
	{
		name: 'http-log',
		label: 'Http Log',
		docUrl: 'http://getkong.org/plugins/http-log/',
		schema: [
			{
				'name':'consumer_id',
				'type' : 'string',
				'label': 'Consumer ID'
			},
			{
				'name':'config.http_endpoint',
				'type' : 'string',
				'label': 'Http Endpoint'
			},
			{
				'name':'config.timeout',
				'type' : 'integer',
				'label': 'Timeout'
			},
			{
				'name':'config.keepalive',
				'type' : 'integer',
				'label': 'Keep Alive'
			},
			{
				'name':'config.method',
				'type' : 'enum',
				'label': 'Method',
				'values': [
					{ 'label' : 'POST', 'value' : 'POST'},
					{ 'label' : 'PATCH', 'value' : 'PATCH'},
					{ 'label' : 'PUT', 'value' : 'PUT'}
				]
			}
		]
	},
	{
		name: 'udp-log',
		label: 'UDP Log',
		docUrl: 'http://getkong.org/plugins/udp-log/',
		schema: [
			{
				'name':'consumer_id',
				'type': 'string',
				'label': 'Consumer ID',
			},
			{
				'name':'config.host',
				'type' : 'string',
				'label': 'Host',
				'required': true
			},
			{
				'name':'config.timeout',
				'type' : 'integer',
				'label': 'Timeout'
			},
			{
				'name':'config.port',
				'type' : 'integer',
				'label': 'Port',
				'required': true
			},
		]
	},
	{
		name: 'tcp-log',
		label: 'TCP Log',
		docUrl: 'http://getkong.org/plugins/tcp-log/',
		schema: [
			{
				'name':'consumer_id',
				'type': 'string',
				'label': 'Consumer ID',
			},
			{
				'name':'config.host',
				'type' : 'string',
				'label': 'Host'
			},
			{
				'name':'config.timeout',
				'type' : 'integer',
				'label': 'Timeout'
			},
			{
				'name':'config.port',
				'type' : 'integer',
				'label': 'Port'
			},
			{
				'name':'config.keepalive',
				'type' : 'integer',
				'label': 'Keep Alive'
			}
		]
	},
	{
		name: 'file-log',
		label: 'File Log',
		docUrl: 'http://getkong.org/plugins/file-log/',
		schema: [
			{
				'name':'consumer_id',
				'type': 'string',
				'label': 'Consumer ID',
			},
			{
				'name':'config.path',
				'type' : 'string',
				'label': 'The Output Path File'
			},
			{
				'name': 'reopen',
				'type' : 'boolean',
				'label': 'Reopen',
			}
		]
	},
	{
		name: 'basic-auth',
		label: 'Basic Authentication',
		docUrl: 'http://getkong.org/plugins/basic-authentication/',
		schema: [
			{
				'name':'config.hide_credentials',
				'type' : 'boolean',
				'label': 'Hide Credentials'
			},
			{
				'name':'config.anonymous',
				'type' : 'string',
				'label': 'Anonymous'
			}
		],
		api : {
			routes : [
				{
					'action': 'list',
					'route': 'consumers/:username/basic-auth',
					'method': 'GET',
					'params': ['username']
				},
				{
					'action': 'create',
					'route': 'consumers/:username/basic-auth',
					'method': 'POST',
					'params': ['username']
				},
				{
					'action': 'view',
					'route': 'consumers/:username/basic-auth/:id',
					'method': 'GET',
					'params': ['username', 'id']
				},
				{
					'action': 'update',
					'route': 'consumers/:username/basic-auth/:id',
					'method': 'PATCH',
					'params': ['username', 'id']
				},
				{
					'action': 'delete',
					'route': 'consumers/:username/basic-auth/:id',
					'method': 'DELETE',
					'params': ['username', 'id']
				}
			],
			dao : [
				{
					'name':'username',
					'type' : 'string',
					'label': 'Username'
				},
				{
					'name':'password',
					'type' : 'string',
					'label': 'Password'
				},
			]
		}
		
	},
	{
		name: 'key-auth',
		label: 'Key Authentication',
		docUrl: 'http://getkong.org/plugins/key-authentication/',
		schema: [
			{
				'name':'config.hide_credentials',
				'type' : 'boolean',
				'label': 'Hide Credentials'
			},
			{
				'name':'config.key_names',
				'type' : 'string',
				'label': 'Key Names'
			},
			{
				'name':'config.anonymous',
				'type' : 'string',
				'label': 'Anonymous'
			},
			{
				'name': 'config.key_in_body',
				'type' : 'enum',
				'label': 'Key In Body'
			}
		],
		api :
			{
				routes : [
					{
						'action': 'list',
						'route': 'consumers/:username/key-auth',
						'method': 'GET',
						'params': ['username']
					},
					{
						'action': 'create',
						'route': 'consumers/:username/key-auth',
						'method': 'POST',
						'params': ['username']
					},
					{
						'action': 'view',
						'route': 'consumers/:username/key-auth/:id',
						'method': 'GET',
						'params': ['username', 'id']
					},
					{
						'action': 'update',
						'route': 'consumers/:username/key-auth/:id',
						'method': 'PATCH',
						'params': ['username', 'id']
					},
					{
						'action': 'delete',
						'route': 'consumers/:username/key-auth/:id',
						'method': 'DELETE',
						'params': ['username', 'id']
					}
				],
				dao : [
					{
						'name':'key',
						'type' : 'string',
						'label': 'Key'
					}
				]
			}
		
	},
	{
		name: 'cors',
		label: 'CORS',
		docUrl: 'http://getkong.org/plugins/cors/',
		schema: [
			{
				'name':'config.origin',
				'type' : 'string',
				'label': 'Origin'
			},
			{
				'name':'config.methods',
				'type' : 'string',
				'label': 'Method'
			},
			{
				'name':'config.headers',
				'type' : 'string',
				'label': 'Headers'
			},
			{
				'name':'config.exposed_headers',
				'type' : 'string',
				'label': 'Exposed Headers'
			},
			{
				'name':'config.credentials',
				'type' : 'boolean',
				'label': 'Credentials'
			},
			{
				'name':'config.max_age',
				'type' : 'integer',
				'label': 'Max Age'
			},
			{
				'name': 'config.preflight_continue',
				'type' : 'boolean',
				'label': 'Preflight Continue'
			}
		]
	},
	{
		name: 'request-transformer',
		label: 'Request Transformer',
		docUrl: 'http://getkong.org/plugins/request-transformer/',
		schema: [
			{
				'name':'consumer_id',
				'type': 'string',
				'label': 'Consumer ID',
			},
				{
				'name':'config.http_method',
				'type': 'enum',
				'label': 'HTTP Method',
				'values': [
					{ 'label' : 'GET', 'value' : 'GET'},
					{ 'label' : 'POST', 'value' : 'POST'},
					{ 'label' : 'PUT', 'value' : 'PUT'},
					{ 'label' : 'PATCH', 'value' : 'PATCH'},
					{ 'label' : 'DELETE', 'value' : 'DELETE'}
				]
			},
			{
				'name':'config.add.headers',
				'type' : 'string',
				'label': 'Headers To Add'
			},
			{
				'name':'config.add.querystring',
				'type' : 'string',
				'label': 'Parameters To Add In Request Querystring'
			},
			{
				'name':'config.add.form',
				'type' : 'string',
				'label': 'Values To Add In Request Body'
			},
			{
				'name':'config.append.headers',
				'type' : 'string',
				'label': 'Headers To Append'
			},
			{
				'name':'config.append.querystring',
				'type' : 'string',
				'label': 'Parameters To Append In Request Querystring'
			},
			{
				'name':'config.append.form',
				'type' : 'string',
				'label': 'Values To Append In Request Body'
			},
			{
				'name':'config.remove.headers',
				'type' : 'string',
				'label': 'Headers To Remove'
			},
			{
				'name':'config.remove.querystring',
				'type' : 'string',
				'label': 'Parameters To Remove In Request Querystring'
			},
			{
				'name':'config.remove.form',
				'type' : 'string',
				'label': 'Values To Remove In Request Body'
			},
			{
				'name':'config.replace.headers',
				'type' : 'string',
				'label': 'Headers To Replace'
			},
			{
				'name':'config.replace.querystring',
				'type' : 'string',
				'label': 'Parameters To Replace In Request Querystring'
			},
			{
				'name':'config.replace.form',
				'type' : 'string',
				'label': 'Values To Replace In Request Body'
			}
		]
	},
	{
		name: 'response-transformer',
		label: 'Response Transformer',
		docUrl: 'http://getkong.org/plugins/response-transformer/',
		schema: [
			{
				'name':'consumer_id',
				'type' : 'string',
				'label': 'Consumer ID'
			},
			{
				'name':'config.add.headers',
				'type' : 'string',
				'label': 'Headers To Add'
			},
			{
				'name':'config.add.json',
				'type' : 'string',
				'label': 'Values To Add To A JSON Response Body'
			},
			{
				'name':'config.append.headers',
				'type' : 'string',
				'label': 'Headers To Append'
			},
			{
				'name':'config.append.json',
				'type' : 'string',
				'label': 'Values To Append To A JSON Response Body'
			},
			{
				'name':'config.remove.headers',
				'type' : 'string',
				'label': 'Headers To Remove'
			},
			{
				'name':'config.remove.json',
				'type' : 'string',
				'label': 'Values To Remove To A JSON Response Body'
			},
				{
				'name':'config.replace.headers',
				'type' : 'string',
				'label': 'Headers To Replace'
			},
			{
				'name':'config.replace.json',
				'type' : 'string',
				'label': 'Values To Replace To A JSON Response Body'
			}
		]
	},
	{
		name: 'rate-limiting',
		label: 'Rate Limiting',
		docUrl: 'http://getkong.org/plugins/rate-limiting/',
		schema: [
			{
				'name':'consumer_id',
				'type' : 'string',
				'label': 'Consumer ID'
			},
			{
				'name':'config.second',
				'type' : 'integer',
				'label': 'Limit (second)'
			},
			{
				'name':'config.minute',
				'type' : 'integer',
				'label': 'Limit (minute)'
			},
			{
				'name':'config.hour',
				'type' : 'integer',
				'label': 'Limit (hour)'
			},
			{
				'name':'config.day',
				'type' : 'integer',
				'label': 'Limit (day)'
			},
			{
				'name':'config.month',
				'type' : 'integer',
				'label': 'Limit (month)'
			},
			{
				'name':'config.year',
				'type' : 'integer',
				'label': 'Limit (year)'
			},
			{
				'name':'config.limit_by',
				'type' : 'enum',
				'label': 'Limit By' ,
				'values': [
					{ 'label' : 'Consumer', 'value' : 'consumer'},
					{ 'label' : 'Credential', 'value' : 'credential'},
					{ 'label' : 'IP Address', 'value' : 'ip'}
				]
			},
			{
				'name':'config.policy',
				'type' : 'enum',
				'label': 'Policy' ,
				'values': [
					{ 'label' : 'Local', 'value' : 'local'},
					{ 'label' : 'Cluster', 'value' : 'cluster'},
					{ 'label' : 'Redis', 'value' : 'redis'}
				]
			},
			{
				'name':'config.fault_tolerant',
				'type' : 'boolean',
				'label': 'Fault Tolerant',
			},
			{
				'name':'config.redis_host',
				'type' : 'string',
				'label': 'Redis Host'
			},
			{
				'name':'config.redis_port',
				'type' : 'integer',
				'label': 'Redis Port'
			},
			{
				'name':'config.redis_password',
				'type' : 'string',
				'label': 'Redis Password'
			},
			{
				'name':'config.redis_timeout',
				'type' : 'integer',
				'label': 'Timeout'
			},
			{
				'name':'config.redis_database',
				'type' : 'integer',
				'label': 'Redis Database'
			},
		]
	},
	{
		name: 'request-size-limiting',
		label: 'Request Size Limiting',
		docUrl: 'http://getkong.org/plugins/request-size-limiting/',
		schema: [
			{
				'name':'consumer_id',
				'type' : 'string',
				'label': 'Consumer ID'
			},
			{
				'name':'config.allowed_payload_size',
				'type' : 'integer',
				'label': 'Allowed Request Payload Size In Megabytes'
			}
		]
	},
	{
		name: 'correlation-id',
		label: 'Correlation ID',
		docUrl: 'https://getkong.org/plugins/correlation-id/',
		schema: [
			{
				'name':'config.header_name',
				'type' : 'string',
				'label': 'Header Name'
			},
			{
				'name':'config.generator',
				'type' : 'enum',
				'label': 'Generator',
				'values': [
					{ 'label' : 'UUID', 'value' : 'uuid'},
					{ 'label' : 'UUID + Counter', 'value' : 'uuid#counter'},
					{ 'label' : 'Tracker', 'value' : 'tracker'}
				]
			},
			{
				'name':'config.echo_downstream',
				'type' : 'boolean',
				'label': 'Echo Header Downstream'
			}
		]
	},
	{
		name: 'response-ratelimiting',
		label: 'Response Rate Limiting',
		docUrl: 'https://getkong.org/plugins/response-ratelimiting/',
		schema: [
				{
				'name':'consumer_id',
				'type' : 'string',
				'label': 'Consumer ID'
			},
			{
				'name':'config.limits.{limit_name}',
				'type' : 'string',
				'label': 'Limit Name'
			},
			{
				'name':'config.limits.{limit_name}.second',
				'type' : 'integer',
				'label': 'Limit (second)'
			},
			{
				'name':'config.limits.{limit_name}.minute',
				'type' : 'integer',
				'label': 'Limit (minute)'
			},
			{
				'name':'config.limits.{limit_name}.hour',
				'type' : 'integer',
				'label': 'Limit (hour)'
			},
			{
				'name':'config.limits.{limit_name}.day',
				'type' : 'integer',
				'label': 'Limit (day)'
			},
			{
				'name':'config.limits.{limit_name}.month',
				'type' : 'integer',
				'label': 'Limit (month)'
			},
			{
				'name':'config.limits.{limit_name}.year',
				'type' : 'integer',
				'label': 'Limit (year)'
			},
			{
				'name':'config.header_name',
				'type' : 'string',
				'label': 'Header Name'
			},
			{
				'name':'config.block_on_first_violation',
				'type' : 'boolean',
				'label': 'Block On First Violation'
			},
			{
				'name':'config.limit_by',
				'type' : 'enum',
				'label': 'Limit By',
				'values': [
					{ 'label' : 'Consumer', 'value' : 'consumer'},
					{ 'label' : 'Credential', 'value' : 'credential'},
					{ 'label' : 'IP', 'value' : 'ip'}
				]
			},
			{
				'name':'config.policy',
				'type' : 'enum',
				'label': 'Policy',
				'values': [
					{ 'label' : 'Local', 'value' : 'local'},
					{ 'label' : 'Cluster', 'value' : 'cluster'},
					{ 'label' : 'Redis', 'value' : 'redis'}
				]
			},
			{
				'name':'config.fault_tolerant',
				'type' : 'boolean',
				'label': 'Fault Tolerant'
			},
			{
				'name':'config.redis_host',
				'type' : 'string',
				'label': 'Redis Host'
			},
			{
				'name':'config.redis_port',
				'type' : 'integer',
				'label': 'Redis Port'
			},
			{
				'name':'config.redis_password',
				'type' : 'string',
				'label': 'Redis Password'
			},
			{
				'name':'config.redis_timeout',
				'type' : 'integer',
				'label': 'Timeout'
			},
			{
				'name':'config.redis_database',
				'type' : 'integer',
				'label': 'Redis Database'
			},
		]
	},
	{
		name: 'request-termination',
		label: 'Request Termination',
		docUrl: 'https://getkong.org/plugins/request-termination/',
		schema: [
			{
				'name':'config.status_code',
				'type' : 'integer',
				'label': 'Status Code'
			},
			{
				'name':'config.message',
				'type' : 'string',
				'label': 'Message'
			},
			{
				'name':'config.body',
				'type' : 'string',
				'label': 'Body'
			},
			{
				'name':'config.content_type',
				'type' : 'string',
				'label': 'Content Type'
			},
		]
	},
	{
		name: 'acl',
		label: 'ACL',
		docUrl: 'https://getkong.org/plugins/acl/',
		schema: [
			{
				'name':'config.whitelist',
				'type' : 'string',
				'label': 'Whitelist'
			},
			{
				'name':'config.blacklist',
				'type' : 'string',
				'label': 'Blacklist'
			}
		]
	},
	{
		name: 'hmac-auth',
		label: 'HMAC Authentication',
		docUrl: 'https://getkong.org/plugins/hmac-authentication/',
		schema: [
			{
				'name':'config.hide_credentials',
				'type' : 'boolean',
				'label': 'Hide Credentials'
			},
			{
				'name':'config.clock_skew',
				'type' : 'integer',
				'label': 'Clock Skew (seconds)'
			},
			{
				'name':'config.anonymous',
				'type' : 'string',
				'label': 'Anonymous'
			}
		]
	},
	{
		name: 'ldap-auth',
		label: 'LDAP Authentication',
		docUrl: 'https://getkong.org/plugins/ldap-authentication/',
		schema: [
			{
				'name':'config.hide_credentials',
				'type' : 'boolean',
				'label': 'Hide Credentials'
			},
			{
				'name':'config.ldap_host',
				'type' : 'string',
				'label': 'Host'
			},
			{
				'name':'config.ldap_port',
				'type' : 'string',
				'label': 'Port'
			},
			{
				'name':'config.start_tls',
				'type' : 'boolean',
				'label': 'Start TLS (Transport Layer Security'
			},
			{
				'name':'config.base_dn',
				'type' : 'string',
				'label': 'Base DN'
			},
			{
				'name':'config.verify_ldap_host',
				'type' : 'boolean',
				'label': 'Verify Host'
			},
			{
				'name':'config.attribute',
				'type' : 'string',
				'label': 'Attribute'
			},
			{
				'name':'config.cache_ttl',
				'type' : 'integer',
				'label': 'Cache TTL (seconds)'
			},
			{
				'name':'config.timeout',
				'type' : 'integer',
				'label': 'Timeout'
			},
			{
				'name':'config.keepalive',
				'type' : 'integer',
				'label': 'Keep Alive'
			},
			{
				'name':'config.anonymous',
				'type' : 'string',
				'label': 'Anonymous'
			}
		]
	},
	{
		name: 'jwt',
		label: 'JWT',
		docUrl: 'https://getkong.org/plugins/jwt/',
		schema: [
			{
				'name':'config.uri_param_names',
				'type' : 'string',
				'label': 'URI Param Names'
			},
			{
				'name':'config.claims_to_verify',
				'type' : 'enum',
				'label': 'Claims To Verify',
				'values': [
					{ 'label' : 'EXP', 'value' : 'exp'},
					{ 'label' : 'NBF', 'value' : 'nbf'}
				]
			},
			{
				'name':'config.key_claim_name',
				'type' : 'string',
				'label': 'Key Claim Name'
			},
			{
				'name':'config.secret_is_base64',
				'type' : 'boolean',
				'label': 'Secret Is Base64'
			},
				{
				'name':'config.anonymous',
				'type' : 'string',
				'label': 'Anonymous'
			}
		]
	},
	{
		name: 'ip-restriction',
		label: 'IP Restriction',
		docUrl: 'https://getkong.org/plugins/ip-restriction/',
		schema: [
			{
				'name':'consumer_id',
				'type': 'string',
				'label': 'Consumer ID',
			},
			{
				'name':'config.whitelist',
				'type' : 'string',
				'label': 'Whitelist'
			},
			{
				'name':'config.blacklist',
				'type' : 'string',
				'label': 'Blacklist'
			}
		]
	},
	{
		name: 'bot-detection',
		label: 'Bot Detection',
		docUrl: 'https://getkong.org/plugins/bot-detection/',
		schema: [
			{
				'name':'config.whitelist',
				'type' : 'string',
				'label': 'Whitelist'
			},
			{
				'name':'config.blacklist',
				'type' : 'string',
				'label': 'Blacklist'
			}
		]
	},
	{
		name: 'aws-lambda',
		label: 'AWL Lambda',
		docUrl: 'https://getkong.org/plugins/aws-lambda/',
		schema: [
			{
				'name':'config.aws_key',
				'type' : 'string',
				'label': 'AWS Key'
			},
			{
				'name':'config.aws_region',
				'type' : 'enum',
				'label': 'AWS Region',
				'values': [
					{ 'label' : 'US-EAST-1', 'value' : 'us-east-1'},
					{ 'label' : 'US-EAST-2', 'value' : 'us-east-2'},
					{ 'label' : 'AP-NORTHEAST-1', 'value' : 'ap-northeast-1'},
					{ 'label' : 'AP-NORTHEAST-2', 'value' : 'ap-northeast-2'},
					{ 'label' : 'AP-SOUTHEAST-1', 'value' : 'ap-southeast-1'},
					{ 'label' : 'AP-SOUTHEAST-2', 'value' : 'ap-southeast-2'},
					{ 'label' : 'EU-CENTRAL-1', 'value' : 'eu-central-1'},
					{ 'label' : 'EU-WEST-1', 'value' : 'eu-west-1'},
				]
			},
			{
				'name':'config.function_name',
				'type' : 'string',
				'label': 'Function Name'
			},
			{
				'name':'config.qualifier',
				'type' : 'string',
				'label': 'Qualifier'
			},
			{
				'name':'config.invocation_type',
				'type' : 'enum',
				'label': 'Invocation Type',
				'values': [
					{ 'label' : 'RequestResponse', 'value' : 'requestresponse'},
					{ 'label' : 'Event', 'value' : 'event'},
					{ 'label' : 'DryRun', 'value' : 'dryrun'}
				]
			},
			{
				'name':'config.log_type',
				'type' : 'enum',
				'label': 'Log Type',
				'values': [
					{ 'label' : 'None', 'value' : 'none'},
					{ 'label' : 'Tail', 'value' : 'tail'},
				]
			},
			{
				'name':'config.timeout',
				'type' : 'integer',
				'label': 'Timeout'
			},
			{
				'name':'config.keepalive',
				'type' : 'integer',
				'label': 'Keep Alive'
			},
		]
	},
	{
		name: 'openwhisk',
		label: 'OpenWhisk',
		docUrl: 'https://getkong.org/plugins/openwhisk/',
		schema: [
			{
				'name':'config.host',
				'type' : 'string',
				'label': 'Host'
			},
			{
				'name':'config.port',
				'type' : 'integer',
				'label': 'Port'
			},
			{
				'name':'config.path',
				'type' : 'string',
				'label': 'The Output Path File'
			},
			{
				'name':'config.action',
				'type' : 'string',
				'label': 'Action to be invoked'
			},
			{
				'name':'config.service_token',
				'type' : 'string',
				'label': 'Service Token'
			},
			{
				'name':'config.https_verify',
				'type' : 'boolean',
				'label': 'Verify HTTPS'
			},
			{
				'name':'config.https',
				'type' : 'boolean',
				'label': 'Use HTTPS'
			},
			{
				'name':'config.result',
				'type' : 'boolean',
				'label': 'Result Of The Action'
			},
			{
				'name':'config.timeout',
				'type' : 'integer',
				'label': 'Timeout'
			},
			{
				'name':'config.keepalive',
				'type' : 'integer',
				'label': 'Keep Alive'
			},
		]
	},
	{
		name: 'syslog',
		label: 'Syslog',
		docUrl: 'https://getkong.org/plugins/syslog/',
		schema: [
			{
				'name':'consumer_id',
				'type': 'string',
				'label': 'Consumer ID',
			},
			{
				'name':'config.successful_severity',
				'type': 'enum',
				'label': 'Successful Severity',
				'values': [
					{ 'label' : 'Emergency', 'value' : 'emerg'},
					{ 'label' : 'Alert', 'value' : 'alert'},
					{ 'label' : 'Critical', 'value' : 'crit'},
					{ 'label' : 'Error', 'value' : 'err'},
					{ 'label' : 'Warning', 'value' : 'warning'},
					{ 'label' : 'Notice', 'value' : 'notice'},
					{ 'label' : 'Informational', 'value' : 'info'},
					{ 'label' : 'Debug', 'value' : 'debug'}
				]
			},
				{
				'name':'config.client_errors_severity',
				'type': 'enum',
				'label': 'Client Errors Severity',
				'values': [
					{ 'label' : 'Emergency', 'value' : 'emerg'},
					{ 'label' : 'Alert', 'value' : 'alert'},
					{ 'label' : 'Critical', 'value' : 'crit'},
					{ 'label' : 'Error', 'value' : 'err'},
					{ 'label' : 'Warning', 'value' : 'warning'},
					{ 'label' : 'Notice', 'value' : 'notice'},
					{ 'label' : 'Informational', 'value' : 'info'},
					{ 'label' : 'Debug', 'value' : 'debug'}
				]
			},
			{
				'name':'config.server_errors_severity',
				'type': 'enum',
				'label': 'Server Errors Severity',
				'values': [
					{ 'label' : 'Emergency', 'value' : 'emerg'},
					{ 'label' : 'Alert', 'value' : 'alert'},
					{ 'label' : 'Critical', 'value' : 'crit'},
					{ 'label' : 'Error', 'value' : 'err'},
					{ 'label' : 'Warning', 'value' : 'warning'},
					{ 'label' : 'Notice', 'value' : 'notice'},
					{ 'label' : 'Informational', 'value' : 'info'},
					{ 'label' : 'Debug', 'value' : 'debug'}
				]
			},
			{
				'name':'config.log_level',
				'type': 'enum',
				'label': 'Log Level',
				'values': [
					{ 'label' : 'Emergency', 'value' : 'emerg'},
					{ 'label' : 'Alert', 'value' : 'alert'},
					{ 'label' : 'Critical', 'value' : 'crit'},
					{ 'label' : 'Error', 'value' : 'err'},
					{ 'label' : 'Warning', 'value' : 'warning'},
					{ 'label' : 'Notice', 'value' : 'notice'},
					{ 'label' : 'Informational', 'value' : 'info'},
					{ 'label' : 'Debug', 'value' : 'debug'}
				]
			}
		]
	},
	{
		name: 'statsd',
		label: 'StatsD',
		docUrl: 'https://getkong.org/plugins/statsd/',
		schema: [
			{
				'name':'consumer_id',
				'type': 'string',
				'label': 'Consumer ID',
			},
			{
				'name':'config.host',
				'type': 'string',
				'label': 'Host',
			},
			{
				'name':'config.port',
				'type' : 'integer',
				'label': 'Port'
			},
			{
				'name':'config.metrics',
				'type' : 'string',
				'label': 'Metrics'
			},
			{
				'name':'config.timeout',
				'type' : 'integer',
				'label': 'Timeout'
			}
		]
	},
	{
		name: 'loggly',
		label: 'Loggly',
		docUrl: 'https://getkong.org/plugins/loggly/',
		schema: [
			{
				'name':'consumer_id',
				'type': 'string',
				'label': 'Consumer ID'
			},
				{
				'name':'config.host',
				'type': 'string',
				'label': 'Host'
			},
			{
				'name':'config.port',
				'type' : 'integer',
				'label': 'Port'
			},
				{
				'name':'config.key',
				'type': 'string',
				'label': 'Access Token'
			},
			{
				'name':'config.tags',
				'type' : 'string',
				'label': 'Tags'
			},
			{
				'name':'config.timeout',
				'type' : 'integer',
				'label': 'Timeout'
			},
			{
				'name':'config.successful_severity',
				'type': 'enum',
				'label': 'Successful Severity',
				'values': [
					{ 'label' : 'Emergency', 'value' : 'emerg'},
					{ 'label' : 'Alert', 'value' : 'alert'},
					{ 'label' : 'Critical', 'value' : 'crit'},
					{ 'label' : 'Error', 'value' : 'err'},
					{ 'label' : 'Warning', 'value' : 'warning'},
					{ 'label' : 'Notice', 'value' : 'notice'},
					{ 'label' : 'Informational', 'value' : 'info'},
					{ 'label' : 'Debug', 'value' : 'debug'}
				]
			},
				{
				'name':'config.client_errors_severity',
				'type': 'enum',
				'label': 'Client Errors Severity',
				'values': [
					{ 'label' : 'Emergency', 'value' : 'emerg'},
					{ 'label' : 'Alert', 'value' : 'alert'},
					{ 'label' : 'Critical', 'value' : 'crit'},
					{ 'label' : 'Error', 'value' : 'err'},
					{ 'label' : 'Warning', 'value' : 'warning'},
					{ 'label' : 'Notice', 'value' : 'notice'},
					{ 'label' : 'Informational', 'value' : 'info'},
					{ 'label' : 'Debug', 'value' : 'debug'}
				]
			},
			{
				'name':'config.server_errors_severity',
				'type': 'enum',
				'label': 'Server Errors Severity',
				'values': [
					{ 'label' : 'Emergency', 'value' : 'emerg'},
					{ 'label' : 'Alert', 'value' : 'alert'},
					{ 'label' : 'Critical', 'value' : 'crit'},
					{ 'label' : 'Error', 'value' : 'err'},
					{ 'label' : 'Warning', 'value' : 'warning'},
					{ 'label' : 'Notice', 'value' : 'notice'},
					{ 'label' : 'Informational', 'value' : 'info'},
					{ 'label' : 'Debug', 'value' : 'debug'}
				]
			},
			{
				'name':'config.log_level',
				'type': 'enum',
				'label': 'Log Level',
				'values': [
					{ 'label' : 'Emergency', 'value' : 'emerg'},
					{ 'label' : 'Alert', 'value' : 'alert'},
					{ 'label' : 'Critical', 'value' : 'crit'},
					{ 'label' : 'Error', 'value' : 'err'},
					{ 'label' : 'Warning', 'value' : 'warning'},
					{ 'label' : 'Notice', 'value' : 'notice'},
					{ 'label' : 'Informational', 'value' : 'info'},
					{ 'label' : 'Debug', 'value' : 'debug'}
				]
			}
		]
	},
	{
		name: 'galileo',
		label: 'Galileo',
		docUrl: 'https://getkong.org/plugins/galileo/',
		schema: [
			{
				'name':'consumer_id',
				'type': 'string',
				'label': 'Consumer ID'
			},
			{
				'name':'config.service_token',
				'type' : 'string',
				'label': 'Service Token'
			},
			{
				'name':'config.environment',
				'type' : 'string',
				'label': 'Environment Name'
			},
			{
				'name':'config.log_bodies',
				'type' : 'boolean',
				'label': 'Capture And Send Request/Response Bodies'
			},
			{
				'name':'config.retry_count',
				'type' : 'integer',
				'label': 'Number Of Retries'
			},
			{
				'name':'config.connection_timeout',
				'type' : 'integer',
				'label': 'Connection Timeout (seconds)'
			},
			{
				'name':'config.flush_timeout',
				'type' : 'integer',
				'label': 'Flush Timeout (seconds)'
			},
			{
				'name':'config.queue_size',
				'type' : 'integer',
				'label': 'Queue Size'
			},
			{
				'name':'config.host',
				'type' : 'string',
				'label': 'Host'
			},
			{
				'name':'config.port',
				'type' : 'integer',
				'label': 'Port'
			},
			{
				'name':'config.https',
				'type' : 'boolean',
				'label': 'Use HTTPS'
			}
		]
	},
	{
		name: 'datadog',
		label: 'Datadog',
		docUrl: 'https://getkong.org/plugins/datadog/',
		schema: [
			{
				'name':'consumer_id',
				'type': 'string',
				'label': 'Consumer ID'
			},
			{
				'name':'config.host',
				'type' : 'string',
				'label': 'Host'
			},
			{
				'name':'config.port',
				'type' : 'integer',
				'label': 'Port'
			},
			{
				'name':'config.metrics',
				'type' : 'string',
				'label': 'Metrics'
			},
			{
				'name':'config.timeout',
				'type' : 'integer',
				'label': 'Timeout'
			}
		]
	},
	{
		name: 'runscope',
		label: 'Runscope',
		docUrl: 'https://getkong.org/plugins/runscope/',
		schema: [
			{
				'name':'config.access_token',
				'type' : 'string',
				'label': 'Access Token'
			},
			{
				'name':'config.bucket_key',
				'type' : 'string',
				'label': 'Bucket ID'
			},
			{
				'name':'config.log_body',
				'type' : 'boolean',
				'label': 'Capture And Send Request/Response Bodies'
			},
				{
				'name':'config.api_endpoint',
				'type' : 'string',
				'label': 'API Endpoint'
			},
				{
				'name':'config.timeout',
				'type' : 'integer',
				'label': 'Timeout'
			},
			{
				'name':'config.keepalive',
				'type' : 'integer',
				'label': 'Keep Alive'
			}
		]
	},
	{
		name: 'oauth2',
		label: 'OAuth 2.0 Authentication',
		docUrl: 'https://getkong.org/plugins/oauth2-authentication/',
		schema: [
			{
				'name':'config.scopes',
				'type' : 'string',
				'label': 'Scope Names'
			},
			{
				'name':'config.mandatory_scope',
				'type' : 'boolean',
				'label': 'Mandatory Scope'
			},
			{
				'name':'config.token_expiration',
				'type' : 'integer',
				'label': 'Token Expiration (seconds)'
			},
			{
				'name':'config.enable_authorization_code',
				'type' : 'boolean',
				'label': 'Enable Authorization Code'
			},
			{
				'name':'config.enable_client_credentials',
				'type' : 'boolean',
				'label': 'Enable Client Credentials'
			},
			{
				'name':'config.enable_implicit_grant',
				'type' : 'boolean',
				'label': 'Enable Implicit Grant'
			},
			{
				'name':'config.enable_password_grant',
				'type' : 'boolean',
				'label': 'Enable Password Grant'
			},
			{
				'name':'config.hide_credentials',
				'type' : 'boolean',
				'label': 'Hide Credentials'
			},
			{
				'name':'config.accept_http_if_already_terminated',
				'type' : 'boolean',
				'label': 'Accept HTTP Requests Even Once Terminated'
			},
			{
				'name':'config.anonymous',
				'type' : 'string',
				'label': 'Anonymous'
			}
		]
	}
]);