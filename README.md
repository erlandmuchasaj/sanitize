# PHP sanitize

---

This is a PHP package that helps to sanatize your input when performing search queries to DB.
It cleans the input from all malicious characters.

## Installation

You can install the package via composer:

```bash
composer require erlandmuchasaj/sanitize
```

## Usage

Sanitize library offers a sanitize method that takes a parameter a dirty string parameter and return a cleaned string.  

```php
use ErlandMuchasaj\Sanitize\Sanitize;

$dirtyString = 'Hello - World';

$sanitizedString = Sanitize::sanitize($dirtyString);

// do something with the sanitized text
// you can: $words = explode(' ', $sanitizedString);
// and search the DB per each word.

```

## Support me
I invest a lot of time and resources into creating [best in class open source packages](https://github.com/erlandmuchasaj?tab=repositories). 
You can support me by [buying me a coffee](https://paypal.me/emcms?country.x=AL&locale.x=en_US).

---

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security Vulnerabilities

If you discover a security vulnerability within this package,
please send an e-mail to Erland Muchasaj via [erland.muchasaj@gmail.com](mailto:erland.muchasaj@gmail.com).
All security vulnerabilities will be promptly addressed.

## Credits

- [Erland Muchasaj](https://github.com/erlandmuchasaj)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
