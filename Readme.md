# Check Password .NET
This library can be used to check the Pwnd Passwords API to determine if the password
has been recovered from breaches. Attackers often use lists of passwords recovered
from breaches to perform password guessing attacks to great success. It is desirable
to avoid using these commonly guessed passwords to keep user accounts safe.

The Pwnd Passwords API version 3, https://haveibeenpwned.com/API/v3, is used by the library
and maintains an up-to-date database of compromised passwords. Huge thanks to Troy Hunt
for maintaining this!

## Use

In its simplest use, a password can be checked with the following code:

```
HIBPClient client = new HIBPClient(new HIBPClientSettings("Your App Name"));
if(client.Check("a user's password")){
    // The user's password is ok
}
```

Various other settings can be applied, including a maximum time to wait for a response from the API, via the HIBPClientSettings object:

```
HIBPClientSettings settings = new HIBPClientSettings("Your App Name") {Timeout=2.0};
HIBPClient client = new HIBPClient(settings);
if(client.Check("a user's password")){
    // The user's password is ok
}
```