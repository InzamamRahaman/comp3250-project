


#define HASH_LEN 40 //this can be changed when we decide on what we're going to use
#define USERNAME_MAX_LEN 50
#define EMAIL_MAX_LEN 254

struct user
{
       int id;
       char username[USERNAME_MAX_LEN+1];
       char password_hash[HASH_LEN+1];
       char *first_name;
       char *last_name;
       char *email[EMAIL_MAX_LEN+1];
};
