# OpenSMTPD-RS
A mass exploitation tool for CVE 2020-8793 (Rust port)

----------------------------------------------------------------------------------

# Info

It's just a Rust port. <br> 
(made in 2 hours, so not fully tested) <br>
Original work can be found [here](https://github.com/helIsec/OpenSMTPD)



The Shodan API to find vulnerable devices and mass sends a payload to the target

To customize the payload :

`stream.write(format!("MAIL FROM:<;{};>\r\n", payload).as_bytes())?;`

Change the variable 'payload' to your desired payload 

----------------------------------------------------------------------------------

# Example

![Example](https://i.imgur.com/TAWuy3Y.png)
