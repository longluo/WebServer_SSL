# SSL Web Server(webserver-ssl)

### English

	This project runs on the EKK-LM3S8962 board. This example application demonstrates the operation of the Stellaris Ethernet controller using the lwIP TCP/IP Stack and MatrixSSL library. DHCP is used to obtain an ethernet address.  If DHCP times out without obtaining an address, an IP address is automatically allocated using the RFC3927 automatic link-local IP address allocation algorithm. The address that is selected will be shown on the OLED display. The file system code will first check to see if an SD card has been plugged into the microSD slot.  If so, all file requests from the web server will be directed to the SD card.  Otherwise, a default set of pages served up by an internal file system will be used.
	
	Requests may be made using HTTPS on port 443 (the default). Unencrypted HTTP is not supported in this example.


### Chinese

	这个项目是在TI的EKK-LM3S8962开发板上运行的。可以实现TLS/SSL协议，我们可以在浏览器中输入https://xxx 进行浏览内容，而输入http://xxx则不能链接到服务器中。
	SSL部分是使用MatrixSSL开源协议栈，TCP/IP协议栈使用的是lwIP 1.3.2版本。
	



