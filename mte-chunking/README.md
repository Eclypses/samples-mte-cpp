# MTE MKE Chunking Demo    

## Introduction
The Managed Key Encryption (MKE) Add-On replaces the core Encoder and Decoder, which only do tokenization, with an Encoder and Decoder that combine standard encryption with tokenization. This allows much larger data to take advantage of the MTE technology without significantly increasing the data size.

The MKE can be used two different ways. The first is identical to how the core MTE operates, encoding and decoding an entire message in one call. The MKE is designed to work with large amounts of data so there may be times when the user does not want to encode and decode all the data in one call. Examples may be when streaming video, audio or uploading a large file. In these cases the MTE MKE chunking calls can be used.

This sample contains a C++ sample that reads in a large file in chunks and saves the encoded data to a new file. After this is completed the encoded file is then read in and decoded, creating a new file with the decoded data.

## Getting Started
This sample is meant to be run locally and does not require an outside API. It does require the user to add their MTE libraries to the code for it to work correctly. 

 - Create a directory named "MTE" in the "testChunker" directory.
 - Copy the "include" directory from the SDK into the "MTE" directory.
 - Copy the "lib" directory from the SDK into the "MTE" directory.
 - Copy the "src/cpp" directory from the SDK into the "MTE" directory.

<div style="page-break-after: always; break-after: page;"></div>

# Contact Eclypses

<p align="center" style="font-weight: bold; font-size: 20pt;">Email: <a href="mailto:info@eclypses.com">info@eclypses.com</a></p>
<p align="center" style="font-weight: bold; font-size: 20pt;">Web: <a href="https://www.eclypses.com">www.eclypses.com</a></p>
<p align="center" style="font-weight: bold; font-size: 20pt;">Chat with us: <a href="https://developers.eclypses.com/dashboard">Developer Portal</a></p>
<p style="font-size: 8pt; margin-bottom: 0; margin: 100px 24px 30px 24px; " >
<b>All trademarks of Eclypses Inc.</b> may not be used without Eclypses Inc.'s prior written consent. No license for any use thereof has been granted without express written consent. Any unauthorized use thereof may violate copyright laws, trademark laws, privacy and publicity laws and communications regulations and statutes. The names, images and likeness of the Eclypses logo, along with all representations thereof, are valuable intellectual property assets of Eclypses, Inc. Accordingly, no party or parties, without the prior written consent of Eclypses, Inc., (which may be withheld in Eclypses' sole discretion), use or permit the use of any of the Eclypses trademarked names or logos of Eclypses, Inc. for any purpose other than as part of the address for the Premises, or use or permit the use of, for any purpose whatsoever, any image or rendering of, or any design based on, the exterior appearance or profile of the Eclypses trademarks and or logo(s).
</p>