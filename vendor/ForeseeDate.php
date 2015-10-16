<?php

class ForeseeDate {
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