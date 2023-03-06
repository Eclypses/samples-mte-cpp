# Diffie-Hellman Key Exchange Handshake Demo    

# Introduction
There are many different ways to exchange information to pair the two devices using the MTE. One way to exchange information when in a zero-knowledge environment is by using the Diffie-Hellman key exchange as a secure way to exchange MTE seed values. This sample demonstrates how to use a Diffie-Hellman Algorithm to exchange the entropy value between two different devices.

This sample contains a C++ client side handshake sample that uses the Eclypses C package to perform the Diffie-Hellman key creation. This also currently runs best in Linux with openssl installed.

# Getting Started
The Handshake sample is meant to be run against a local API or the Eclypses public sample API. Ensure the correct rest api host url and port are set in the Constants.h file near the beginning before compiling and running the sample.

<div style="page-break-after: always; break-after: page;"></div>

# Contact Eclypses

<p align="center" style="font-weight: bold; font-size: 22pt;">For more information, please contact:</p>
<p align="center" style="font-weight: bold; font-size: 22pt;"><a href="mailto:info@eclypses.com">info@eclypses.com</a></p>
<p align="center" style="font-weight: bold; font-size: 22pt;"><a href="https://www.eclypses.com">www.eclypses.com</a></p>
<p align="center" style="font-weight: bold; font-size: 22pt;">+1.719.323.6680</p>

<p style="font-size: 8pt; margin-bottom: 0; margin: 300px 24px 30px 24px; " >
<b>All trademarks of Eclypses Inc.</b> may not be used without Eclypses Inc.'s prior written consent. No license for any use thereof has been granted without express written consent. Any unauthorized use thereof may violate copyright laws, trademark laws, privacy and publicity laws and communications regulations and statutes. The names, images and likeness of the Eclypses logo, along with all representations thereof, are valuable intellectual property assets of Eclypses, Inc. Accordingly, no party or parties, without the prior written consent of Eclypses, Inc., (which may be withheld in Eclypses' sole discretion), use or permit the use of any of the Eclypses trademarked names or logos of Eclypses, Inc. for any purpose other than as part of the address for the Premises, or use or permit the use of, for any purpose whatsoever, any image or rendering of, or any design based on, the exterior appearance or profile of the Eclypses trademarks and or logo(s).
</p>