# spring-session-sso
A cross domain Single sign on &amp; Single log out authentication example using Spring Session. Read this [post](https://beku8.wordpress.com/2016/09/12/configuring-cross-domain-sso-and-slo-with-spring-security-and-spring-session/).

#Running the app#
This is just a regular spring boot, maven project, created in *STS 3.8*. So easiest way is to import it into [STS](https://spring.io/tools/sts) or any other
Eclipse based IDE. 

Run the *login server* first and open it on [http://localhost:8080](http://localhost:8080). 
*Client1* app will run on the port ```9090```, but run it [http://127.0.0.1:9090/](http://127.0.0.1:9090/) not *localhost*, so
these 2 apps won't share session id from the browser
