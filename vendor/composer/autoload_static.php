<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit4a15679e03dc1b7e7474dfee70ca0a2b
{
    public static $prefixLengthsPsr4 = array (
        'E' => 
        array (
            'ErlandMuchasaj\\Sanitize\\' => 24,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'ErlandMuchasaj\\Sanitize\\' => 
        array (
            0 => __DIR__ . '/../..' . '/src',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
        'ErlandMuchasaj\\Sanitize\\Sanitize' => __DIR__ . '/../..' . '/src/Sanitize.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit4a15679e03dc1b7e7474dfee70ca0a2b::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit4a15679e03dc1b7e7474dfee70ca0a2b::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInit4a15679e03dc1b7e7474dfee70ca0a2b::$classMap;

        }, null, ClassLoader::class);
    }
}