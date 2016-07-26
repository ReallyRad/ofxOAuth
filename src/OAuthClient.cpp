#include "OAuthClient.h"

using namespace ofxOAuth;

OAuthClient::OAuthClient(std::string json_file) {
	bool result = mOAuthConfigFile.open(json_file);

	mConsumer = NULL;
	mClient = NULL;
	mAuthorizationToken = NULL;

	if (result) {
		std::printf("ofxOAuth::OAuthClient -- Successfully parsed OAuth parameters!\n");
		mConsumer = std::make_shared<OAuth::Consumer>(mOAuthConfigFile["consumer_key"].asString(), mOAuthConfigFile["consumer_secret"].asString());

		if (!mOAuthConfigFile["access_token"].asString().empty()) {
			mAuthorizationToken = std::make_shared<OAuth::Token>(mOAuthConfigFile["access_token"].asString(), mOAuthConfigFile["access_token_secret"].asString());
			mClient = std::make_shared<OAuth::Client>(mConsumer.get(), mAuthorizationToken.get());
		}
		else {
			std::printf("ofxOAuth::OAuthClient -- no access tokens found; you must authorize this client first.\n");
			mClient = std::make_shared<OAuth::Client>(mConsumer.get());
		}

		mCurl = ofxCurl::Curl::make();
	}
	else {
		std::printf("ofxOAuth::OAuthClient ERROR -- Uable to parse OAuth parameters!\n");
	}
}

OAuthClient::~OAuthClient() {

}

void OAuthClient::authorize() {
	/* 
	incomplete method! 
	This would eventually allow you to automaticall authorize the application.
	*/

	if (mConsumer) {
		std::string request_url = mOAuthConfigFile["request_token_url"].asString();
		std::string request_url_query_args = mOAuthConfigFile["request_token_query_args"].asString();
		if (!request_url_query_args.empty()) {
			request_url += "?";
			request_url += request_url_query_args;
		}

		std::string query_url = mClient->getURLQueryString(OAuth::Http::Get, request_url);
		std::string full_url = request_url + "&" + query_url;

		std::string token_response = mCurl->get(full_url);

		OAuth::Token authorization_token = OAuth::Token::extract(token_response);

		std::string token_url = mOAuthConfigFile["authorize_url"].asString() + "?oath_token=" + authorization_token.key();

		std::printf("ofxOAuth::OAuthClient::authorize -- Please go to %s to authorize the token.\n", token_url.c_str());
	}
	else {
		std::printf("ofxOAuth::OAuthClient::authorize -- Unable to authorize; OAuth was not able to generate a Consumer.  Check your Consumer Key and Consumer Secret!\n");
	}
}

std::string OAuthClient::getResource(std::string resource_url, std::string parameters) {
	std::string request_url = resource_url + "?" + parameters;

	std::string oauth_url = mClient->getURLQueryString(OAuth::Http::Get, request_url);
	std::string full_url = resource_url + "?" + oauth_url;

	std::string output = mCurl->get(full_url);
	return output;
}

std::string OAuthClient::getResource(std::string resource_url, std::map<std::string, std::string> parameters) {
	std::string parameterString = mCurl->mapToString(parameters);
	std::string request_url = resource_url + "?" + parameterString;

	std::string oauth_url = mClient->getURLQueryString(OAuth::Http::Get, request_url);
	std::string full_url = resource_url + "?" + oauth_url;

	std::string output = mCurl->get(oauth_url);
	return output;
}

std::string OAuthClient::postResource(std::string resource_url, std::string parameters) {
	std::string request_url = resource_url + "?" + parameters;

	std::string oauth_url = mClient->getURLQueryString(OAuth::Http::Post, request_url, parameters);
	std::string full_url = resource_url + "?" + oauth_url;

	std::string output = mCurl->post(full_url);
	return output;
}

std::string OAuthClient::postResource(std::string resource_url, std::map<std::string, std::string> parameters) {
	std::string parameterString = mCurl->mapToString(parameters);
	std::string request_url = resource_url + "?" + parameterString;

	std::string oauth_url = mClient->getURLQueryString(OAuth::Http::Post, request_url, parameterString);
	std::string full_url = resource_url + "?" + oauth_url;

	std::string output = mCurl->post(full_url);
	return output;
}
