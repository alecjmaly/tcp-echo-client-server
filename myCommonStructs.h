typedef struct {
		unsigned int principal_id;
		unsigned int public_key;
	} key_to_principal_mesg;
	typedef struct {
		enum {register_user,request_key} request_type;   /* same size as an unsigned int */
		unsigned int principal_id;   /* client or broker identifier */
		unsigned int public_key;     /* client's RSA public key */
    } principal_to_key_mesg;	     /* an unsigned int is 32 bits = 4 bytes */
	typedef struct {
		enum {buy, sell, confirm, done} request_type; // same size as an unsigned int
		unsigned int client_id;					// client identifier
		unsigned int transaction_id;			// transaction identifier
		unsigned int num_stocks;				// number of stocks
	} client_broker_mesg;
	static const char *client_broker_request_type[] = {
		"buy", "sell", "confirm", "done",
	};
	static const char *keyManager_request_type[] = {
		"Register User", "Request Key",
	};
