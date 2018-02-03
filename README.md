
# `password_exposed` helper function

[![Build Status](https://travis-ci.org/DivineOmega/password_exposed.svg?branch=master)](https://travis-ci.org/DivineOmega/password_exposed)
[![Coverage Status](https://coveralls.io/repos/github/DivineOmega/password_exposed/badge.svg?branch=master)](https://coveralls.io/github/DivineOmega/password_exposed?branch=master)
[![StyleCI](https://styleci.io/repos/119845896/shield?branch=master)](https://styleci.io/repos/119845896)

This PHP package provides an `password_exposed` helper function, that uses the haveibeenpwned.com API to check if a password has been exposed in a data breach.

## Installation

The `password_exposed` package can be easily installed using Composer. Just run the following command from the root of your project.

```
composer require "divineomega/password_exposed"
```

If you have never used the Composer dependency manager before, head to the [Composer website](https://getcomposer.org/) for more information on how to get started.

## Usage

To check if a password has been exposed in a data breach, just pass it to the `is_offensive` method.

Here are a few examples:

```php
is_offensive('test');  // true
is_offensive('password');   // true
is_offensive('hunter2');  // true

is_offensive('cat bike duck cheese monkey fat');   // false (hopefully!)
```
