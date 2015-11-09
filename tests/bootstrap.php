<?php
/**
 * Bootstrap the tests
 *
 * PHP version 5.2
 *
 * @category   OAuthTest
 * @author     Pieter Hordijk <info@pieterhordijk.com>
 * @author     David Desberg  <david@daviddesberg.com>
 * @copyright  Copyright (c) 2012 Pieter Hordijk
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */
namespace AcsTest;

/**
 * Setting up the default timezone. because well... PHP sucks
 */
date_default_timezone_set('Etc/UTC');

/**
 * Simple SPL autoloader for the OAuthTest mocks
 *
 * @param string $class The class name to load
 *
 * @return void
 */
spl_autoload_register(function ($class) {
    $nslen = strlen(__NAMESPACE__);
    if (substr($class, 0, $nslen) !== __NAMESPACE__) {
        return;
    }
    $path = substr(str_replace('\\', '/', $class), $nslen);
    $path = __DIR__ . $path . '.php';
    if (file_exists($path)) {
        require $path;
    }
});