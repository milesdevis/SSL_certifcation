## To make a SSL connection and to view the SSL certificate:

Clone this repo 

Note that the URL to establish the connection with is hard coded into dest_url in the main function.  To change the URL, change **dest_url**.

Then, run the following to compile :
```
rm sslconnect
gcc -o sslconnect sslconnect.c -lssl -lyrcypto
```

Then, to run the program: 
```
./sslconnect
```
