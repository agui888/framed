<?php

// $_GET['host'] = 'api.hehe.com';

if ( !isset($_GET['host']) ) {
	exit(json_encode(array(
		'code' => 404001,
		'message' => 'xxx'
	)));
}

$host = $_GET['host'];

$info = array(
	// host
	'api.hehe.com' => array(
		// basePath
		'/v0' => array(
			'project_id' => 12345,
			'project_version' => '1234567890',
		),
		'/fucking' => array(
			'project_id' => 908536,
			'project_version' => '1234567890',
			'callers' => array(
				array(
					"caller_id" => 1122,
					"auth_mode" => "apikey",  //anonymous|apikey|iplist|basic
					"apikey" => "hahahahahahahahahaha123",
					"basic_auth_username" => "",
					"basic_auth_username" => "",
					// "ip_list" => ["110.123.111.142"],

					// ===== 访问规则如下 =====   
					// 也可以只有当 status == True 时再传对应的规则，看你的需求。
					"rate_limit_per_period" =>  array("day" => 1000, "hour" => 60, "minute" => 5),
					"rate_limit_per_period_status" => true,
					"ip_black_list" => [],
					"ip_black_list_status" => true, 
					"ip_white_list" =>  [],
					"ip_white_list_status" => false,
					"referer_list" => [],
					"referer_status" => true,
					"rw_rights" => "r",  //r、rw
				),
				array(
					"caller_id" => 1,
					"auth_mode" => "basic",  //anonymous|apikey|iplist|basic
					"apikey" => "",
					"basic_auth_username" => "smcz",
					"basic_auth_password" => "1234",
					// "ip_list" => ["110.123.111.142"],

					// ===== 访问规则如下 =====   
					// 也可以只有当 status == True 时再传对应的规则，看你的需求。
					"rate_limit_per_period" =>  array("day" => 1000, "hour" => 200, "minute" => 20),
					"rate_limit_per_period_status" => true,
					"ip_black_list" => [],
					"ip_black_list_status" => true, 
					"ip_white_list" =>  [],
					"ip_white_list_status" => false,
					"referer_list" => [],
					"referer_status" => true,
					"rw_rights" => "rw",  //r、rw
				),
				array(
					"caller_id" => 0,
					"auth_mode" => "anonymous",  //anonymous|apikey|iplist|basic
					"apikey" => "",
					"basic_auth_username" => "smcz",
					"basic_auth_password" => "1234",
					// "ip_list" => ["110.123.111.142"],

					// ===== 访问规则如下 =====   
					// 也可以只有当 status == True 时再传对应的规则，看你的需求。
					"rate_limit_per_period" =>  array("day" => 1000, "hour" => 200, "minute" => 20),
					"rate_limit_per_period_status" => true,
					"ip_black_list" => [],
					"ip_black_list_status" => true, 
					"ip_white_list" =>  [],
					"ip_white_list_status" => false,
					"referer_list" => [],
					"referer_status" => true,
					"rw_rights" => "rw",  //r、rw
				),
			),
			'apis' => array(),
			'routers' => array(
				'/boy' => array(
					'api_info_id' => 123,
					'backend_type' => 'proxy',
					'request_methods' => array('post', 'get'),
					'backend_url' => 'http://baidu.com',
					'status' => 'on',
					'timeout' => 60,
				),
				'/girl' => array(
					'api_info_id' => 123,
					'backend_type' => 'proxy',
					'request_methods' => array('post', 'get'),
					'backend_url' => 'http://baidu.com',
					'status' => 'on',
					'timeout' => 60,
				),
				'/man' => array(
					'api_info_id' => 123,
					'backend_type' => 'proxy',
					'request_methods' => array('post', 'get'),
					'backend_url' => 'http://baidu.com',
					'status' => 'on',
					'timeout' => 60,
				),
			),
		),
		'/v1' => array(
			'project_id' => 1234,
			'project_version' => '1234567890',
			'callers' => array(
				array(
					"caller_id" => 1122,
					"auth_mode" => "apikey",  //anonymous|apikey|iplist|basic
					"apikey" => "hahahahahahahahahaha123",
					"basic_auth_username" => "",
					"basic_auth_username" => "",
					// "ip_list" => ["110.123.111.142"],

					// ===== 访问规则如下 =====   
					// 也可以只有当 status == True 时再传对应的规则，看你的需求。
					"rate_limit_per_period" =>  array("day" => 1000, "hour" => 60, "minute" => 5),
					"rate_limit_per_period_status" => true,
					"ip_black_list" => [],
					"ip_black_list_status" => true, 
					"ip_white_list" =>  [],
					"ip_white_list_status" => false,
					"referer_list" => [],
					"referer_status" => true,
					"rw_rights" => "r",  //r、rw
				),
				array(
					"caller_id" => 1,
					"auth_mode" => "basic",  //anonymous|apikey|iplist|basic
					"apikey" => "",
					"basic_auth_username" => "smcz",
					"basic_auth_password" => "1234",
					// "ip_list" => ["110.123.111.142"],

					// ===== 访问规则如下 =====   
					// 也可以只有当 status == True 时再传对应的规则，看你的需求。
					"rate_limit_per_period" =>  array("day" => 1000, "hour" => 200, "minute" => 20),
					"rate_limit_per_period_status" => true,
					"ip_black_list" => [],
					"ip_black_list_status" => true, 
					"ip_white_list" =>  [],
					"ip_white_list_status" => false,
					"referer_list" => [],
					"referer_status" => true,
					"rw_rights" => "rw",  //r、rw
				),
				array(
					"caller_id" => 0,
					"auth_mode" => "anonymous",  //anonymous|apikey|iplist|basic
					"apikey" => "",
					"basic_auth_username" => "smcz",
					"basic_auth_password" => "1234",
					// "ip_list" => ["110.123.111.142"],

					// ===== 访问规则如下 =====   
					// 也可以只有当 status == True 时再传对应的规则，看你的需求。
					"rate_limit_per_period" =>  array("day" => 1000, "hour" => 200, "minute" => 20),
					"rate_limit_per_period_status" => true,
					"ip_black_list" => [],
					"ip_black_list_status" => true, 
					"ip_white_list" =>  [],
					"ip_white_list_status" => false,
					"referer_list" => [],
					"referer_status" => true,
					"rw_rights" => "rw",  //r、rw
				),
			),
			'apis' => array(
				'/pet' => array(
					'methods' => array(
						'get' => array(
							'backend_type' => 'a2a',
							'api_info_id' => 345,
							'status' => 'on',
						),
						'post' => array(
							'backend_type' => 'd2a',
							'api_info_id' => 145,
							'status' => 'on',
						)
					),
				),
				'/pet/act_{id}/info' => array(
					'methods' => array(
						'get' => array(
							'backend_type' => 'a2a',
							'api_info_id' => 3451,
							'status' => 'on',
						),
						'post' => array(
							'backend_type' => 'd2a',
							'api_info_id' => 3145,
							'status' => 'on',
						)
					)
				),
			),
		),
		'/v2' => array(
			'project_id' => 4321,
			'project_version' => '1234567890',
			'callers' => array(
				array(
					"caller_id" => 0,
					"auth_mode" => "anonymous",  //anonymous|apikey|iplist|basic
					"apikey" => "",
					"basic_auth_username" => "",
					"basic_auth_username" => "",
					// "ip_list" => ["110.123.111.142"],

					// ===== 访问规则如下 =====   
					// 也可以只有当 status == True 时再传对应的规则，看你的需求。
					"rate_limit_per_period" =>  array("day" => 1000, "hour" => 200, "minute" => 20),
					"rate_limit_per_period_status" => true,
					"ip_black_list" => [],
					"ip_black_list_status" => true, 
					"ip_white_list" =>  [],
					"ip_white_list_status" => false,
					"referer_list" => [],
					"referer_status" => true,
					"rw_rights" => "rw",  //r、rw
				),
				array(
					"caller_id" => 1,
					"auth_mode" => "basic",  //anonymous|apikey|iplist|basic
					"apikey" => "",
					"basic_auth_username" => "smcz",
					"basic_auth_password" => "1234",
					// "ip_list" => ["110.123.111.142"],

					// ===== 访问规则如下 =====   
					// 也可以只有当 status == True 时再传对应的规则，看你的需求。
					"rate_limit_per_period" =>  array("day" => 1000, "hour" => 200, "minute" => 20),
					"rate_limit_per_period_status" => true,
					"ip_black_list" => [],
					"ip_black_list_status" => true, 
					"ip_white_list" =>  [],
					"ip_white_list_status" => false,
					"referer_list" => [],
					"referer_status" => true,
					"rw_rights" => "rw",  //r、rw
				),
			),
			'apis' => array(
				'/pet' => array(
					'methods' => array(
						'get' => array(
							'backend_type' => 'a2a',
							'api_info_id' => 12345,
							'status' => 'off',
						),
						'post' => array(
							'backend_type' => 'd2a',
							'api_info_id' => 34531,
							'status' => 'on',
						)
					)
				),
				'/pet/{id}' => array(
					
					'methods' => array(
						'get' => array(
							'backend_type' => 'a2a',
							'api_info_id' => 33445,
							'status' => 'on',
						),
						'post' => array(
							'backend_type' => 'd2a',
							'api_info_id' => 33445,
							'status' => 'on',
						)
					)
				),
			),
			
		),
		'/' => array(
			'project_id' => 4321,
			'project_version' => '1234567890',
			'callers' => array(
				array(
					"caller_id" => 0,
					"auth_mode" => "anonymous",  //anonymous|apikey|iplist|basic
					"apikey" => "",
					"basic_auth_username" => "",
					"basic_auth_username" => "",
					// "ip_list" => ["110.123.111.142"],

					// ===== 访问规则如下 =====   
					// 也可以只有当 status == True 时再传对应的规则，看你的需求。
					"rate_limit_per_period" =>  array("day" => 1000, "hour" => 200, "minute" => 20),
					"rate_limit_per_period_status" => true,
					"ip_black_list" => [],
					"ip_black_list_status" => true, 
					"ip_white_list" =>  [],
					"ip_white_list_status" => false,
					"referer_list" => [],
					"referer_status" => true,
					"rw_rights" => "rw",  //r、rw
				),
				array(
					"caller_id" => 1,
					"auth_mode" => "basic",  //anonymous|apikey|iplist|basic
					"apikey" => "",
					"basic_auth_username" => "smcz",
					"basic_auth_password" => "1234",
					// "ip_list" => ["110.123.111.142"],

					// ===== 访问规则如下 =====   
					// 也可以只有当 status == True 时再传对应的规则，看你的需求。
					"rate_limit_per_period" =>  array("day" => 1000, "hour" => 200, "minute" => 20),
					"rate_limit_per_period_status" => true,
					"ip_black_list" => [],
					"ip_black_list_status" => true, 
					"ip_white_list" =>  [],
					"ip_white_list_status" => false,
					"referer_list" => [],
					"referer_status" => true,
					"rw_rights" => "rw",  //r、rw
				),
			),
			'apis' => array(
				'pet' => array(
					'methods' => array(
						'get' => array(
							'backend_type' => 'a2a',
							'api_info_id' => 12345,
							'status' => 'on',
						),
						'post' => array(
							'backend_type' => 'd2a',
							'api_info_id' => 34531,
							'status' => 'on',
						)
					)
				),
				'/pet/{id}' => array(
					
					'methods' => array(
						'get' => array(
							'backend_type' => 'a2a',
							'api_info_id' => 33445,
							'status' => 'on',
						),
						'post' => array(
							'backend_type' => 'd2a',
							'api_info_id' => 33445,
							'status' => 'on',
						)
					)
				),
			),
			
		),
	)
);

if ( isset($info[$host]) ) {
	echo json_encode(array(
		'projects' => $info[$host],
	));
} else {
	exit(json_encode(array(
		'code' => 404001,
		'message' => 'xxx'
	)));
}