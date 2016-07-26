#include <memory>
#include <string>
#include <map>
#include "liboauthcpp.h"
#include "ofxJSON.h"
#include "ofxCurl.h"

/*
In order to use this class, you need to give it a path to a json file with the following structure:

{
"consumer_key" : "",
"consumer_secret" : "",
"access_token" : "",
"access_token_secret" : "",
"request_token_url" : "https://api.twitter.com/oauth/request_token",
"request_token_query_args" : "oauth_callback=oob",
"authorize_url" : "https://api.twitter.com/oauth/authorize", // optional for authorization
"access_token_url" : "https://api.twitter.com/oauth/access_token" // optional for authorization
}
*/

namespace ofxOAuth {

class OAuthClient {
public:
	OAuthClient(std::string json_path);
	~OAuthClient();
	void authorize();
	std::string getResource(std::string resource_url, std::string parameters);
	std::string getResource(std::string resource_url, std::map<std::string, std::string> parameters);
	std::string postResource(std::string resource_url, std::string parameters);
	std::string postResource(std::string resource_url, std::map<std::string, std::string> parameters);

protected:
	ofxJSONElement mOAuthConfigFile;
	std::shared_ptr<ofxCurl::Curl> mCurl;
	std::shared_ptr<OAuth::Consumer> mConsumer;
	std::shared_ptr<OAuth::Client> mClient;
	std::shared_ptr<OAuth::Token> mAuthorizationToken;
};

}