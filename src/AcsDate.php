<?php
/**
 * The MIT License (MIT)
 * Copyright (c) 2015 Answers Cloud Services
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @copyright Answers Cloud Services
 * @author Matthew Stuart <matthew.stuart@answers.com>
 */

/**
 * ACS Date Support Library
 * Defines function and other tasks related to the logic surrounding ACS API Date Objects
 */
class AcsDate {
    /**
     * Parses and creates an ACS date object for use with ACS API filtering
     * See README for more information on possible options.
     *
     * @param string $client
     * @param string|\DateTime $from
     * @param string|\DateTime $to
     * @param string $style
     * @param bool|false $fiscal
     * @param string $option
     * @return array|bool
     */
    public static function create($client, $from, $to, $style, $fiscal = false, $option = null)
    {
        if ($from && !($from instanceof \DateTime)) {
            $from = static::parseDateTime($from);
        }
        if ($to && !($to instanceof \DateTime)) {
            $to = static::parseDateTime($to);
        }

        $fiscal = (strtoupper((string)$fiscal) === "FISCAL" || $fiscal === true);

        if ($from instanceof \DateTime) {
            $block = array(
                "c" => $fiscal ? "F" : "G",
                "r" => "DY",
                "p" => $style == "PRIORPERIOD" ? "P" : "D",
                "n" => 10,
                "a" => $from->format("Y-m-d"),
                "f" => "",
                "l" => "",
                "k" => (string)$client,
                "v" => "",
                "o" => false
            );
            if ($to instanceof \DateTime) {
                $block['r'] = "C";
                $block['n'] = 0;
                $block['f'] = $from->format("Y-m-d");
                $block['l'] = $to->format("Y-m-d");
                $block['o'] = true;
            }

            return $block;
        }

        if (is_string($from)) {
            $block = array(
                "c" => $fiscal ? "F" : "G",
                "r" => "",
                "p" => $style == "PRIORPERIOD" ? "P" : "D",
                "n" => 0,
                "a" => "",
                "f" => "",
                "l" => "",
                "k" => (string)$client,
                "v" => "",
                "o" => true
            );

            switch (strtoupper($from)) {
                case 'WEEKTODATE':
                    $block["r"] = "W";
                    break;

                case 'LASTWEEK':
                    $block["r"] = "W";
                    $block["n"] = 1;
                    break;

                case 'YETSERDAY':
                    $block["r"] = "D";
                    $block["n"] = 1;
                    break;

                case 'MONTHTODATE':
                    $block["r"] = "M";
                    break;

                case 'LAStMONTH':
                    $block["r"] = "M";
                    $block["n"] = 1;
                    break;

                case 'QUARTERTODATE':
                    $block["r"] = "Q";
                    break;

                case 'LASTQUARTER':
                    $block["r"] = "Q";
                    $block["n"] = 1;
                    break;

                case 'YEARTODATE':
                    $block["r"] = "Y";
                    break;

                case 'LASTYEAR':
                    $block["r"] = "Y";
                    $block["n"] = 1;
                    break;

                case 'LAST':
                    $block['r'] = "Y";
                    if ($option) {
                        $first = substr(strtoupper($option), 0, 1);
                        if (in_array($first, array('D', 'W', 'M', 'Y'))) {
                            $block['r'] = $first;
                        }
                    }
                    $block["n"] = intval($to);
                    break;
                default:
                    $block = false;
                    break;
            }

            return $block;
        }

        return false;
    }

    /**
     * Helper function to convert a string to an instance of \DateTime
     * @param string|]\DateTime $date
     * @return DateTime
     */
    public static function parseDateTime($date)
    {
        if ($date instanceof \DateTime) {
            return $date;
        }

        if ($parsed = @strtotime($date)) {
            return new \DateTime("@$parsed");
        }
        return $date;
    }
}