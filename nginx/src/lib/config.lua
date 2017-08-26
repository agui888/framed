local conf = {
    ["api_config_core_api"] = "http://apix.applinzi.com/project.php",
    ["acl_redis"] = {
        -- {
        --     ["ip"] = "192.168.0.89",
        --     ["port"] = 6375
        -- },
        {
            ["ip"] = "192.168.229.200",
            ["port"] = 6379
        }
    },
    ["api_config_http_uri"] = "http://192.168.0.23:8088/getvalue",
    --check whether the backend is a private ip
    ["backend_filter_status"] = "on",
    ["backend_filter_white_list"] = {
        ["192.168.1.12"] = true,
        ["a.test.com"] = true
    },
    ["nginx_num"] = 4,
    ["api_adapter_test_ip"] = "123.59.102.50",
    ["sync_sleep_time_s"] = "0.1",
    ["ws_send_sleep_time_s"] = "0.1",
    ["ws_receive_sleep_time_s"] = "0.1",
    ["filter_url"] = "http://192.168.0.23:8080/v1/internal/data/filter",
    ["taskqueue_url"] = "http://192.168.0.23:8080/v1/internal/taskqueue/job",
    ["websocket_url"] = "http://192.168.0.23:8080/v1/internal/longloop/job",
    ["notify_nginx_url"] = "http://192.168.0.89:8090/sempost",
    ["sign_key"] = "9ae8c6ff58b0f7d6504de51d75744a28",
    ["sign_timeout"] = 120,
    ["rate_white_black_url"] = "http://192.168.0.23:8080/v1/internal/security/ip",
    ["rate_white_list_expire"] = 0,
    ["rate_black_list_expire"] = 3600,
    ["rate_black_number"] = 5,
    ["rate_vcode_html"] = [[
<html lang="en">
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
		<title>请输入验证码</title>
		<style type="text/css">
			* {
				margin:0;
				padding:0;
			}
			body {
				background-color:#EFEFEF;
				font: .9em "Lucida Sans Unicode", "Lucida Grande", sans-serif;
			}

			.captcha {
			    display: inline-block;
			    float: right;
			    width: 85px;
			    height: 32px;
			    border-radius: 2px;
			}

			.vcode {
				line-height: 1;
			    height: 32px;
			    margin: 0;
			    padding: 0 10px;
			    -webkit-transition: all .25s ease;
			    transition: border .25s ease;
			    text-align: left;
			    color: #3d444f;
			    border: 1px solid #ccd1d9;
			    border-radius: 2px;
			    outline: 0;
			    background-color: #fff;
			    box-shadow: none;
			}

			#wrapper{
				width:600px;
				margin:40px auto 0;
				text-align:center;
				-moz-box-shadow: 5px 5px 10px rgba(0,0,0,0.3);
				-webkit-box-shadow: 5px 5px 10px rgba(0,0,0,0.3);
				box-shadow: 5px 5px 10px rgba(0,0,0,0.3);
			}
			#wrapper h1, #wrapper h2, #wrapper h3, #wrapper h4 {
				color:#FFF;
				text-align:center;
				/*margin-bottom:20px;*/
				margin-top: 7px;
			}
			#wrapper a {
				display:block;
				font-size:.9em;
				padding-top:20px;
				color:#FFF;
				text-decoration:none;
				text-align:center;
			}
			#container {
				width:600px;
				padding-bottom:15px;
				background-color:#FFFFFF;
			}
			.navtop{
				height:40px;
				background-color:#24B2EB;
				padding:13px;
			}
			.content {
				padding:10px 10px 25px;
				background: #FFFFFF;
				margin:;
				color:#333;
				text-align: center;
			}
			.button{
				color:white;
				width: 100px;
				padding:10px 15px;
				text-shadow:1px 1px 0 #00A5FF;
				font-weight:bold;
				text-align:center;
				border:1px solid #24B2EB;
				margin:0px 200px;
				clear:both;
				background-color: #24B2EB;
				border-radius:10px;
				-moz-border-radius:10px;
				-webkit-border-radius:10px;
			}
			a.button:hover{
				text-decoration:none;
				background-color: #24B2EB;
			}
		</style>
		<script type=text/javascript src="https://lib.sinaapp.com/js/jquery/2.0.3/jquery-2.0.3.min.js"></script>

		<script>
			$(document).ready(function(){
				$("#button").click(function() {
					  var vcode = $("#vcode").val();
					  $.post("%s", {
						  vcode: vcode
					  }, function(data) {
						  if ( data && data['errno'] == 0 ) {
							  location.reload();
						  } else {
							  $("#error_msg").html(data['error']);
						  }
					  }, 'json');
				});
			})
		</script>
	</head>
	<body>
		<div id="wrapper">
			<div id="container">
				<div class="navtop">
					<h2>请输入验证码</h2>
				</div>
				<div id="content" style="width:264px;  margin:20px auto;">
					<input id="vcode" type="text" value="" class="vcode">
					<img class="captcha" id="yan" src="%s" onclick="this.src='%s&d='+Math.random();"/>
				</div>
				<button id="button" class="button">确定</button>
				<br><br>
				<span id="error_msg" style="color:red;"></span>
			</div>
		</div>
	</body>
</html>
]]

}

local _M = {};
local modelName = "config";
_G[modelName] = _M;

function _M.get_conf(key)
	return conf[key]
end

return _M
