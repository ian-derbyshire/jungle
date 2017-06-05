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
				'label': 'Keepalive'
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
				'label': 'Keepalive'
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
				'type' : 'enum',
				'label': 'Reopen',
				'values': [
					{ 'label' : 'True', 'value' : 'true'},
					{ 'label' : 'False', 'value' : 'false'}
				]
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
				'type' : 'enum',
				'label': 'Preflight Continue'
			}
		]
	},
	{
		name: 'dynamic-ssl',
		label: 'Dynamic SSL',
		docUrl: 'https://getkong.org/plugins/dynamic-ssl/',
		schema: [
			{
				'name':'config.cert',
				'type' : 'string',
				'label': 'Certificate File Path'
			},
			{
				'name':'config.key',
				'type' : 'string',
				'label': 'Certificate Key Path'
			},
			{
				'name':'config.only_https',
				'type' : 'boolean',
				'label': 'Only HTTPS'
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
				'type' : 'enum',
				'label': 'Fault Tolerant',
				'values': [
					{ 'label' : 'True', 'value' : 'true'},
					{ 'label' : 'False', 'value' : 'false'}
				]
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
	}
]);