//this sturct stores the information about users(mimicks the database cloumns)
struct proxy_server_users
{
       int id;
       char username[50];
       char password[200];
       char fname[50];
       char lname[60];
       int age;
       char country[50];
};
