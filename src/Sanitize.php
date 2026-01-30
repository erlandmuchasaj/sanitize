<?php

declare(strict_types=1);

namespace ErlandMuchasaj\Sanitize;

use Transliterator;

/**
 * Sanitize input strings for use in search queries.
 * 
 * Handles HTML stripping, whitespace normalization, accent removal,
 * and character filtering with options for email and hyphen preservation.
 */
final class Sanitize
{
    /**
     * Unicode punctuation character class (derived from Drupal search module).
     * Modified to preserve hyphen character.
     */
    private const PREG_CLASS_PUNCTUATION = '\x{21}-\x{23}\x{25}-\x{2a}\x{2c}-\x{2f}\x{3a}\x{3b}\x{3f}\x{40}\x{5b}-\x{5d}'.
        '\x{5f}\x{7b}\x{7d}\x{a1}\x{ab}\x{b7}\x{bb}\x{bf}\x{37e}\x{387}\x{55a}-\x{55f}'.
        '\x{589}\x{58a}\x{5be}\x{5c0}\x{5c3}\x{5f3}\x{5f4}\x{60c}\x{60d}\x{61b}\x{61f}'.
        '\x{66a}-\x{66d}\x{6d4}\x{700}-\x{70d}\x{964}\x{965}\x{970}\x{df4}\x{e4f}'.
        '\x{e5a}\x{e5b}\x{f04}-\x{f12}\x{f3a}-\x{f3d}\x{f85}\x{104a}-\x{104f}\x{10fb}'.
        '\x{1361}-\x{1368}\x{166d}\x{166e}\x{169b}\x{169c}\x{16eb}-\x{16ed}\x{1735}'.
        '\x{1736}\x{17d4}-\x{17d6}\x{17d8}-\x{17da}\x{1800}-\x{180a}\x{1944}\x{1945}'.
        '\x{2010}-\x{2027}\x{2030}-\x{2043}\x{2045}-\x{2051}\x{2053}\x{2054}\x{2057}'.
        '\x{207d}\x{207e}\x{208d}\x{208e}\x{2329}\x{232a}\x{23b4}-\x{23b6}\x{2768}-'.
        '\x{2775}\x{27e6}-\x{27eb}\x{2983}-\x{2998}\x{29d8}-\x{29db}\x{29fc}\x{29fd}'.
        '\x{3001}-\x{3003}\x{3008}-\x{3011}\x{3014}-\x{301f}\x{3030}\x{303d}\x{30a0}'.
        '\x{30fb}\x{fd3e}\x{fd3f}\x{fe30}-\x{fe52}\x{fe54}-\x{fe61}\x{fe63}\x{fe68}'.
        '\x{fe6a}\x{fe6b}\x{ff01}-\x{ff03}\x{ff05}-\x{ff0a}\x{ff0c}-\x{ff0f}\x{ff1a}'.
        '\x{ff1b}\x{ff1f}\x{ff20}\x{ff3b}-\x{ff3d}\x{ff3f}\x{ff5b}\x{ff5d}\x{ff5f}-'.
        '\x{ff65}';

    private const PREG_CLASS_NUMBERS = '\x{30}-\x{39}\x{b2}\x{b3}\x{b9}\x{bc}-\x{be}\x{660}-\x{669}\x{6f0}-\x{6f9}'.
        '\x{966}-\x{96f}\x{9e6}-\x{9ef}\x{9f4}-\x{9f9}\x{a66}-\x{a6f}\x{ae6}-\x{aef}'.
        '\x{b66}-\x{b6f}\x{be7}-\x{bf2}\x{c66}-\x{c6f}\x{ce6}-\x{cef}\x{d66}-\x{d6f}'.
        '\x{e50}-\x{e59}\x{ed0}-\x{ed9}\x{f20}-\x{f33}\x{1040}-\x{1049}\x{1369}-'.
        '\x{137c}\x{16ee}-\x{16f0}\x{17e0}-\x{17e9}\x{17f0}-\x{17f9}\x{1810}-\x{1819}'.
        '\x{1946}-\x{194f}\x{2070}\x{2074}-\x{2079}\x{2080}-\x{2089}\x{2153}-\x{2183}'.
        '\x{2460}-\x{249b}\x{24ea}-\x{24ff}\x{2776}-\x{2793}\x{3007}\x{3021}-\x{3029}'.
        '\x{3038}-\x{303a}\x{3192}-\x{3195}\x{3220}-\x{3229}\x{3251}-\x{325f}\x{3280}-'.
        '\x{3289}\x{32b1}-\x{32bf}\x{ff10}-\x{ff19}';

    private const PREG_CLASS_SEARCH_EXCLUDE = '\x{0}-\x{2c}\x{2e}-\x{2f}\x{3a}-\x{40}\x{5b}-\x{60}\x{7b}-\x{bf}\x{d7}\x{f7}\x{2b0}-'.
        '\x{385}\x{387}\x{3f6}\x{482}-\x{489}\x{559}-\x{55f}\x{589}-\x{5c7}\x{5f3}-'.
        '\x{61f}\x{640}\x{64b}-\x{65e}\x{66a}-\x{66d}\x{670}\x{6d4}\x{6d6}-\x{6ed}'.
        '\x{6fd}\x{6fe}\x{700}-\x{70f}\x{711}\x{730}-\x{74a}\x{7a6}-\x{7b0}\x{901}-'.
        '\x{903}\x{93c}\x{93e}-\x{94d}\x{951}-\x{954}\x{962}-\x{965}\x{970}\x{981}-'.
        '\x{983}\x{9bc}\x{9be}-\x{9cd}\x{9d7}\x{9e2}\x{9e3}\x{9f2}-\x{a03}\x{a3c}-'.
        '\x{a4d}\x{a70}\x{a71}\x{a81}-\x{a83}\x{abc}\x{abe}-\x{acd}\x{ae2}\x{ae3}'.
        '\x{af1}-\x{b03}\x{b3c}\x{b3e}-\x{b57}\x{b70}\x{b82}\x{bbe}-\x{bd7}\x{bf0}-'.
        '\x{c03}\x{c3e}-\x{c56}\x{c82}\x{c83}\x{cbc}\x{cbe}-\x{cd6}\x{d02}\x{d03}'.
        '\x{d3e}-\x{d57}\x{d82}\x{d83}\x{dca}-\x{df4}\x{e31}\x{e34}-\x{e3f}\x{e46}-'.
        '\x{e4f}\x{e5a}\x{e5b}\x{eb1}\x{eb4}-\x{ebc}\x{ec6}-\x{ecd}\x{f01}-\x{f1f}'.
        '\x{f2a}-\x{f3f}\x{f71}-\x{f87}\x{f90}-\x{fd1}\x{102c}-\x{1039}\x{104a}-'.
        '\x{104f}\x{1056}-\x{1059}\x{10fb}\x{10fc}\x{135f}-\x{137c}\x{1390}-\x{1399}'.
        '\x{166d}\x{166e}\x{1680}\x{169b}\x{169c}\x{16eb}-\x{16f0}\x{1712}-\x{1714}'.
        '\x{1732}-\x{1736}\x{1752}\x{1753}\x{1772}\x{1773}\x{17b4}-\x{17db}\x{17dd}'.
        '\x{17f0}-\x{180e}\x{1843}\x{18a9}\x{1920}-\x{1945}\x{19b0}-\x{19c0}\x{19c8}'.
        '\x{19c9}\x{19de}-\x{19ff}\x{1a17}-\x{1a1f}\x{1d2c}-\x{1d61}\x{1d78}\x{1d9b}-'.
        '\x{1dc3}\x{1fbd}\x{1fbf}-\x{1fc1}\x{1fcd}-\x{1fcf}\x{1fdd}-\x{1fdf}\x{1fed}-'.
        '\x{1fef}\x{1ffd}-\x{2070}\x{2074}-\x{207e}\x{2080}-\x{2101}\x{2103}-\x{2106}'.
        '\x{2108}\x{2109}\x{2114}\x{2116}-\x{2118}\x{211e}-\x{2123}\x{2125}\x{2127}'.
        '\x{2129}\x{212e}\x{2132}\x{213a}\x{213b}\x{2140}-\x{2144}\x{214a}-\x{2b13}'.
        '\x{2ce5}-\x{2cff}\x{2d6f}\x{2e00}-\x{3005}\x{3007}-\x{303b}\x{303d}-\x{303f}'.
        '\x{3099}-\x{309e}\x{30a0}\x{30fb}\x{30fd}\x{30fe}\x{3190}-\x{319f}\x{31c0}-'.
        '\x{31cf}\x{3200}-\x{33ff}\x{4dc0}-\x{4dff}\x{a015}\x{a490}-\x{a716}\x{a802}'.
        '\x{e000}-\x{f8ff}\x{fb29}\x{fd3e}-\x{fd3f}\x{fdfc}-\x{fdfd}'.
        '\x{fd3f}\x{fdfc}-\x{fe6b}\x{feff}-\x{ff0f}\x{ff1a}-\x{ff20}\x{ff3b}-\x{ff40}'.
        '\x{ff5b}-\x{ff65}\x{ff70}\x{ff9e}\x{ff9f}\x{ffe0}-\x{fffd}';

    /**
     * Cached Transliterator instance for performance.
     */
    private static ?Transliterator $transliterator = null;

    /**
     * Prevent instantiation - this is a static utility class.
     */
    private function __construct()
    {
    }

    /**
     * Sanitize a string for use in search queries.
     *
     * @param string $string      The input string to sanitize
     * @param bool   $keepHyphens Whether to preserve hyphens (default: false)
     * @param bool   $keepEmails  Whether to preserve email format (default: false)
     */
    public static function sanitize(
        string $string = '',
        bool $keepHyphens = false,
        bool $keepEmails = false
    ): string {
        $string = trim($string);

        if ($string === '') {
            return '';
        }

        // Ensure valid UTF-8 encoding
        $string = self::ensureUtf8($string);

        // Remove HTML tags
        $string = strip_tags($string);

        // Decode HTML entities
        $string = html_entity_decode($string, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Transliterate accented characters to ASCII equivalents
        $string = self::transliterate($string);

        // Convert to lowercase
        $string = mb_strtolower($string, 'UTF-8');

        // Remove punctuation between numbers (e.g., "1,000" → "1000", "1.5" → "15")
        $string = self::removePunctuationBetweenNumbers($string);

        // Handle special characters based on email preservation setting
        if (!$keepEmails) {
            $string = self::removeSearchExcludedCharacters($string);
            // Replace dots and underscores with spaces (not remove!)
            $string = str_replace(['.', '_'], ' ', $string);
        }

        // Handle hyphens
        if (!$keepHyphens) {
            $string = self::normalizeHyphens($string);
        }

        // Normalize whitespace to single spaces
        $string = self::normalizeWhitespace($string);

        return trim($string);
    }

    /**
     * Transliterate accented/special characters to ASCII equivalents.
     * 
     * Uses ICU Transliterator (preferred), falls back to iconv, then manual replacement.
     */
    public static function transliterate(string $string): string
    {
        // Try ICU Transliterator first (most comprehensive)
        if (class_exists(Transliterator::class)) {
            $transliterator = self::getTransliterator();

            if ($transliterator !== null) {
                $result = $transliterator->transliterate($string);

                if ($result !== false) {
                    return $result;
                }
            }
        }

        // Fallback to iconv transliteration
        if (function_exists('iconv')) {
            // Set locale for better transliteration
            $currentLocale = setlocale(LC_CTYPE, '0');
            setlocale(LC_CTYPE, 'en_US.UTF-8', 'C.UTF-8');

            $result = @iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $string);

            // Restore locale
            if ($currentLocale !== false) {
                setlocale(LC_CTYPE, $currentLocale);
            }

            if ($result !== false) {
                return $result;
            }
        }

        // Final fallback to manual character replacement
        return self::replaceAccentedChars($string);
    }

    /**
     * Check if the intl extension with Transliterator is available.
     */
    public static function hasIntlSupport(): bool
    {
        return class_exists(Transliterator::class) && self::getTransliterator() !== null;
    }

    /**
     * Ensure string is valid UTF-8.
     */
    private static function ensureUtf8(string $string): string
    {
        if (!mb_check_encoding($string, 'UTF-8')) {
            // Attempt to convert from detected encoding or strip invalid sequences
            $encoding = mb_detect_encoding($string, ['UTF-8', 'ISO-8859-1', 'Windows-1252'], true);

            if ($encoding !== false && $encoding !== 'UTF-8') {
                return mb_convert_encoding($string, 'UTF-8', $encoding);
            }

            // Strip invalid UTF-8 sequences
            return mb_convert_encoding($string, 'UTF-8', 'UTF-8');
        }

        return $string;
    }

    /**
     * Get or create cached Transliterator instance.
     */
    private static function getTransliterator(): ?Transliterator
    {
        if (self::$transliterator === null) {
            // NFD: Decompose characters (é → e + combining accent)
            // Remove combining marks (accents)
            // NFC: Recompose
            // Latin-ASCII: Convert remaining to ASCII
            self::$transliterator = Transliterator::createFromRules(
                ':: NFD; :: [:Nonspacing Mark:] Remove; :: NFC; :: Latin-ASCII;',
                Transliterator::FORWARD
            );
        }

        return self::$transliterator;
    }

    /**
     * Remove punctuation between consecutive number sequences.
     */
    private static function removePunctuationBetweenNumbers(string $string): string
    {
        $pattern = '/([' . self::PREG_CLASS_NUMBERS . ']+)[' . self::PREG_CLASS_PUNCTUATION . ']+(?=[' . self::PREG_CLASS_NUMBERS . '])/u';

        return (string) preg_replace($pattern, '$1', $string);
    }

    /**
     * Remove characters that should be excluded from search.
     */
    private static function removeSearchExcludedCharacters(string $string): string
    {
        $pattern = '/[' . self::PREG_CLASS_SEARCH_EXCLUDE . ']+/u';

        return (string) preg_replace($pattern, ' ', $string);
    }

    /**
     * Normalize hyphens - replace with spaces except at word boundaries.
     */
    private static function normalizeHyphens(string $string): string
    {
        // Replace all hyphens/dashes with spaces
        return (string) preg_replace('/[\x{2010}-\x{2015}\-]+/u', ' ', $string);
    }

    /**
     * Normalize multiple whitespace characters to single space.
     */
    private static function normalizeWhitespace(string $string): string
    {
        return (string) preg_replace('/\s+/', ' ', $string);
    }

    /**
     * Manual fallback for replacing accented characters.
     * Used when neither Transliterator nor iconv are available.
     */
    private static function replaceAccentedChars(string $str): string
    {
        static $map = null;

        if ($map === null) {
            $map = self::buildAccentMap();
        }

        return strtr($str, $map);
    }

    /**
     * Build character replacement map for manual transliteration.
     * Using strtr with a map is faster than multiple preg_replace calls.
     */
    private static function buildAccentMap(): array
    {
        return [
            // Lowercase Latin
            'à' => 'a', 'á' => 'a', 'â' => 'a', 'ã' => 'a', 'ä' => 'a', 'å' => 'a',
            'ā' => 'a', 'ă' => 'a', 'ą' => 'a', 'æ' => 'ae',
            'ç' => 'c', 'ć' => 'c', 'ĉ' => 'c', 'č' => 'c',
            'ď' => 'd', 'đ' => 'd',
            'è' => 'e', 'é' => 'e', 'ê' => 'e', 'ë' => 'e', 'ē' => 'e', 'ĕ' => 'e',
            'ė' => 'e', 'ę' => 'e', 'ě' => 'e',
            'ğ' => 'g', 'ĝ' => 'g', 'ġ' => 'g', 'ģ' => 'g',
            'ĥ' => 'h', 'ħ' => 'h',
            'ì' => 'i', 'í' => 'i', 'î' => 'i', 'ï' => 'i', 'ĩ' => 'i', 'ī' => 'i',
            'ĭ' => 'i', 'į' => 'i', 'ı' => 'i',
            'ĵ' => 'j',
            'ķ' => 'k', 'ĸ' => 'k',
            'ĺ' => 'l', 'ļ' => 'l', 'ľ' => 'l', 'ŀ' => 'l', 'ł' => 'l',
            'ñ' => 'n', 'ń' => 'n', 'ņ' => 'n', 'ň' => 'n', 'ŉ' => 'n', 'ŋ' => 'n',
            'ò' => 'o', 'ó' => 'o', 'ô' => 'o', 'õ' => 'o', 'ö' => 'o', 'ø' => 'o',
            'ō' => 'o', 'ŏ' => 'o', 'ő' => 'o', 'œ' => 'oe',
            'ŕ' => 'r', 'ŗ' => 'r', 'ř' => 'r',
            'ś' => 's', 'ŝ' => 's', 'ş' => 's', 'š' => 's', 'ß' => 'ss',
            'ţ' => 't', 'ť' => 't', 'ŧ' => 't',
            'ù' => 'u', 'ú' => 'u', 'û' => 'u', 'ü' => 'u', 'ũ' => 'u', 'ū' => 'u',
            'ŭ' => 'u', 'ů' => 'u', 'ű' => 'u', 'ų' => 'u',
            'ŵ' => 'w',
            'ý' => 'y', 'ÿ' => 'y', 'ŷ' => 'y',
            'ź' => 'z', 'ż' => 'z', 'ž' => 'z',

            // Uppercase Latin
            'À' => 'A', 'Á' => 'A', 'Â' => 'A', 'Ã' => 'A', 'Ä' => 'A', 'Å' => 'A',
            'Ā' => 'A', 'Ă' => 'A', 'Ą' => 'A', 'Æ' => 'AE',
            'Ç' => 'C', 'Ć' => 'C', 'Ĉ' => 'C', 'Č' => 'C',
            'Ď' => 'D', 'Đ' => 'D',
            'È' => 'E', 'É' => 'E', 'Ê' => 'E', 'Ë' => 'E', 'Ē' => 'E', 'Ĕ' => 'E',
            'Ė' => 'E', 'Ę' => 'E', 'Ě' => 'E',
            'Ğ' => 'G', 'Ĝ' => 'G', 'Ġ' => 'G', 'Ģ' => 'G',
            'Ĥ' => 'H', 'Ħ' => 'H',
            'Ì' => 'I', 'Í' => 'I', 'Î' => 'I', 'Ï' => 'I', 'Ĩ' => 'I', 'Ī' => 'I',
            'Ĭ' => 'I', 'Į' => 'I', 'İ' => 'I',
            'Ĵ' => 'J',
            'Ķ' => 'K',
            'Ĺ' => 'L', 'Ļ' => 'L', 'Ľ' => 'L', 'Ŀ' => 'L', 'Ł' => 'L',
            'Ñ' => 'N', 'Ń' => 'N', 'Ņ' => 'N', 'Ň' => 'N', 'Ŋ' => 'N',
            'Ò' => 'O', 'Ó' => 'O', 'Ô' => 'O', 'Õ' => 'O', 'Ö' => 'O', 'Ø' => 'O',
            'Ō' => 'O', 'Ŏ' => 'O', 'Ő' => 'O', 'Œ' => 'OE',
            'Ŕ' => 'R', 'Ŗ' => 'R', 'Ř' => 'R',
            'Ś' => 'S', 'Ŝ' => 'S', 'Ş' => 'S', 'Š' => 'S',
            'Ţ' => 'T', 'Ť' => 'T', 'Ŧ' => 'T',
            'Ù' => 'U', 'Ú' => 'U', 'Û' => 'U', 'Ü' => 'U', 'Ũ' => 'U', 'Ū' => 'U',
            'Ŭ' => 'U', 'Ů' => 'U', 'Ű' => 'U', 'Ų' => 'U',
            'Ŵ' => 'W',
            'Ý' => 'Y', 'Ŷ' => 'Y', 'Ÿ' => 'Y',
            'Ź' => 'Z', 'Ż' => 'Z', 'Ž' => 'Z',

            // Cyrillic (Russian/Ukrainian)
            'а' => 'a', 'б' => 'b', 'в' => 'v', 'г' => 'g', 'д' => 'd', 'е' => 'e',
            'ё' => 'yo', 'ж' => 'zh', 'з' => 'z', 'и' => 'i', 'й' => 'j', 'к' => 'k',
            'л' => 'l', 'м' => 'm', 'н' => 'n', 'о' => 'o', 'п' => 'p', 'р' => 'r',
            'с' => 's', 'т' => 't', 'у' => 'u', 'ф' => 'f', 'х' => 'kh', 'ц' => 'c',
            'ч' => 'ch', 'ш' => 'sh', 'щ' => 'shh', 'ъ' => '', 'ы' => 'y', 'ь' => '',
            'э' => 'e', 'ю' => 'yu', 'я' => 'ya',
            'і' => 'i', 'ї' => 'yi', 'є' => 'ye', 'ґ' => 'g',

            'А' => 'A', 'Б' => 'B', 'В' => 'V', 'Г' => 'G', 'Д' => 'D', 'Е' => 'E',
            'Ё' => 'YO', 'Ж' => 'ZH', 'З' => 'Z', 'И' => 'I', 'Й' => 'J', 'К' => 'K',
            'Л' => 'L', 'М' => 'M', 'Н' => 'N', 'О' => 'O', 'П' => 'P', 'Р' => 'R',
            'С' => 'S', 'Т' => 'T', 'У' => 'U', 'Ф' => 'F', 'Х' => 'KH', 'Ц' => 'C',
            'Ч' => 'CH', 'Ш' => 'SH', 'Щ' => 'SHH', 'Ъ' => '', 'Ы' => 'Y', 'Ь' => '',
            'Э' => 'E', 'Ю' => 'YU', 'Я' => 'YA',
            'І' => 'I', 'Ї' => 'YI', 'Є' => 'YE', 'Ґ' => 'G',

            // Vietnamese
            'ạ' => 'a', 'ả' => 'a', 'ấ' => 'a', 'ầ' => 'a', 'ẩ' => 'a', 'ẫ' => 'a',
            'ậ' => 'a', 'ắ' => 'a', 'ằ' => 'a', 'ẳ' => 'a', 'ẵ' => 'a', 'ặ' => 'a',
            'ẹ' => 'e', 'ẻ' => 'e', 'ẽ' => 'e', 'ế' => 'e', 'ề' => 'e', 'ể' => 'e',
            'ễ' => 'e', 'ệ' => 'e',
            'ỉ' => 'i', 'ị' => 'i',
            'ọ' => 'o', 'ỏ' => 'o', 'ố' => 'o', 'ồ' => 'o', 'ổ' => 'o', 'ỗ' => 'o',
            'ộ' => 'o', 'ớ' => 'o', 'ờ' => 'o', 'ở' => 'o', 'ỡ' => 'o', 'ợ' => 'o',
            'ơ' => 'o', 'Ơ' => 'O',
            'ụ' => 'u', 'ủ' => 'u', 'ứ' => 'u', 'ừ' => 'u', 'ử' => 'u', 'ữ' => 'u',
            'ự' => 'u', 'ư' => 'u', 'Ư' => 'U',
            'ỳ' => 'y', 'ỵ' => 'y', 'ỷ' => 'y', 'ỹ' => 'y',
            'đ' => 'd', 'Đ' => 'D',
        ];
    }
}
