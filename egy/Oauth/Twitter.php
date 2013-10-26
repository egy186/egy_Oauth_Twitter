<?php

/**
 * egyOauth for Twitter
 * http://github.com/egy186/egy_Oauth_Twitter
 *
 * OAuth library for Twitter REST API v1.1
 *
 * Copyright (c) 2013 egy186
 * Released under the MIT license.
 */

namespace egy\Oauth;

/**
 * egy\Oauth\Twitter
 */
class Twitter {
//region Settings
    // Oauth config
    private $oauth_config = array();
    // Contains information
    private $egy_info = array();
//endregion

//region cURL Settings
    // Connect timeout
    public $curl_connecttimeout = 30;
    // Timeout
    public $curl_timeout = 30;
    // User agent
    private $curl_user_agent = 'egy Oauth for Twitter v1.0.0a';
    // Verify SSL
    public $curl_ssl_verifypeer = false;
//endregion

/**
     * Construct egy\Oauth\Twitter
     *
     * @param string $consumer_key       your oauth consumer key
     * @param string $consumer_secret    your oauth consumer secret
     * @param string $oauth_token        
     * @param string $oauth_token_secret
     */
    public function __construct($consumer_key, $consumer_secret, $oauth_token = null, $oauth_token_secret = null) {
        $this->oauth_config['consumer_key'] = $consumer_key;
        $this->oauth_config['consumer_secret'] = $consumer_secret;
        $this->oauth_config['oauth_token'] = $oauth_token;
        $this->oauth_config['oauth_token_secret'] = $oauth_token_secret;
    }
    
    /**
     * make Twitter API request
     *
     * @param  string $url
     * @param  string $method
     * @param  array  $parameters
     * @return string $response
     */
    public function APIRequest($url, $method, $parameters = array()) {
        $method = strtoupper($method);
        $oauth_signature = array(
            'oauth_consumer_key' => $this->oauth_config['consumer_key'],
            'oauth_nonce' => md5(uniqid(rand(), true)),
            'oauth_signature_method' => 'HMAC-SHA1',
            'oauth_timestamp' => time(),
            'oauth_token' => $this->oauth_config['oauth_token'],
            'oauth_version' => '1.0'
        );
        if($method != 'POST') {
            $oauth_signature += $parameters;
        }

        $ch = curl_init();
        curl_setopt_array($ch,
            array(
                CURLOPT_CONNECTTIMEOUT => $this->curl_connecttimeout,
                CURLOPT_HTTPHEADER => array(
                    $this->generateAuthHead($url, $method, $oauth_signature),
                    //'Expect:',
                    //'Accept:'
                ),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_SSL_VERIFYPEER => $this->curl_ssl_verifypeer,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_TIMEOUT => $this->curl_timeout,
                CURLOPT_USERAGENT => $this->curl_user_agent
            )
        );
        switch($method) {
            case 'POST':
                curl_setopt($ch, CURLOPT_POST, true);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $parameters);
                break;
            case 'GET':
                curl_setopt($ch, CURLOPT_HTTPHEADER, 'Content-Length: 0');
                if($parameters) {
                    $url .= '?' . http_build_query($parameters);
                }
                break;
        }
        curl_setopt($ch, CURLOPT_URL, $url);
        //curl_setopt($ch, CURLINFO_HEADER_OUT, true); //for debug
        $response = curl_exec($ch);

        $this->egy_info['curl_info'] = curl_getinfo($ch);
        curl_close($ch);
        return $response;
    }

//region Get token
    /**
     * wrapper of getToken for getting request token
     *
     * @param  string $callbackURL
     * @return array  $token       ['oauth_token'], ['oauth_token_secret']
     */
    public function getRequestToken($callbackURL) {
        return $this->getToken($this->requestTokenURL(), array('oauth_callback' => $callbackURL));
    }

    /**
     * wrapper of getToken for getting oauth token
     *
     * @param  string $oauth_verifier
     * @return array  $token          ['oauth_token'], ['oauth_token_secret'],
     *                                ['user_id'], ['screen_name']
     */
    public function getOAuthToken($oauth_verifier) {
        return $this->getToken($this->accessTokenURL(), array('oauth_verifier' => $oauth_verifier));
    }

    /**
     * get token
     *
     * @param  string $url
     * @param  array  $parameters
     * @return array  $token
     */
    private function getToken($url, $parameters = array()) {
        $method = 'POST';
        $oauth_signature = array(
            'oauth_consumer_key' => $this->oauth_config['consumer_key'],
            'oauth_nonce' => md5(uniqid(rand(), true)),
            'oauth_signature_method' => 'HMAC-SHA1',
            'oauth_timestamp' => time(),
            'oauth_version' => '1.0'
        );
        if (isset($this->oauth_config['oauth_token'])) {
            $oauth_signature['oauth_token'] = $this->oauth_config['oauth_token'];
        }
        $oauth_signature += $parameters;

        $ch = curl_init($url);
        curl_setopt_array($ch,
            array(
                CURLOPT_CONNECTTIMEOUT => $this->curl_connecttimeout,
                CURLOPT_HTTPHEADER => array(
                    $this->generateAuthHead($url, $method, $oauth_signature),
                    'Content-Length: 0'
                ),
                CURLOPT_POST => true,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_SSL_VERIFYPEER => $this->curl_ssl_verifypeer,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_TIMEOUT => $this->curl_timeout,
                CURLOPT_USERAGENT => $this->curl_user_agent
            )
        );
        $response = curl_exec($ch);

        $this->egy_info['curl_info'] = curl_getinfo($ch);
        curl_close($ch);
        parse_str($response, $token);
        return $token;
    }
//endregion
    
//region Utils
    // request token
    public function requestTokenURL() { return 'https://api.twitter.com/oauth/request_token'; }
    // access token
    public function accessTokenURL() { return 'https://api.twitter.com/oauth/access_token'; }
    // authorize
    public function authorizeURL() { return 'https://api.twitter.com/oauth/authorize'; }

    /**
     * generate HTTP header 'Authorization:'
     *
     * @param  string $url
     * @param  string $method
     * @param  array  $parameters
     * @return string $header ex. 'Authorization: OAuth oauth_...'
     */
    private function generateAuthHead($url, $method, $parameters) {
        ksort($parameters);
        $signature = http_build_query($parameters, PHP_QUERY_RFC3986);
        $signature = $method . '&' . rawurlencode($url) . '&' . rawurlencode($signature);

        $signing_key = rawurlencode($this->oauth_config['consumer_secret']) . '&'
                        . rawurlencode($this->oauth_config['oauth_token_secret']);

        $parameters['oauth_signature'] = base64_encode(hash_hmac(
            'sha1',
            $signature,
            $signing_key,
            true
        ));

        $header = 'Authorization: OAuth ';
        foreach($parameters as $key => $val) {
            if (substr($key, 0, 5) != 'oauth') {
                continue;
            }
            $header .= $key . '="' . rawurlencode($val) . '",';
        }
        $header = substr($header, 0, -1);
        return $header;
    }

    /**
     * Help debugging
     *
     * @param  void
     * @return array
     */
    public function getInfo() {
        return $egy_info;
    }
//endregion
}
/* EOF */
