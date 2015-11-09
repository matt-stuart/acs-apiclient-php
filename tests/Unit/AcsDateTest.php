<?php

namespace AcsTest\Unit;

require_once __DIR__ . '/../../src/AcsDate.php';

class AcsDateTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @group AcsDate
     * @group parseDateTime
     */
    public function testParseDateTime()
    {
        $instance = $this->getMockBuilder('\AcsDate')->setMethods(null)->getMock();

        $date = new \DateTime();
        $this->assertSame($date, $instance::parseDateTime($date));

        $date = "invalid";
        $this->assertSame($date, $instance::parseDateTime($date));

        $string = "midnight";
        $date = new \DateTime($string);
        $this->assertEquals($date, $instance::parseDateTime($string));
    }

    /**
     * @group AcsDate
     * @group create
     */
    public function testCreate()
    {
        $instance = $this->getMockBuilder('\AcsDate')->setMethods(null)->getMock();

        $this->assertTrue(is_array(
            $instance::create(
                'clientid',
                '2015-01-01',
                '2015-02-01',
                'PRIORPERIOD',
                true
            )
        ));

        $this->assertTrue(is_array(
            $instance::create(
                'clientid',
                '2015-01-01',
                '2015-02-01',
                'STANDARD',
                false
            )
        ));

        $this->assertTrue(is_array(
            $instance::create(
                'clientid',
                'LAST',
                '3',
                'standard',
                true,
                'DAYS'
            )
        ));

        $this->assertTrue(is_array(
            $instance::create(
                'clientid',
                'LASTYEAR',
                null,
                null,
                true
            )
        ));

        $this->assertTrue(is_array(
            $instance::create(
                'clientid',
                'YEARTODATE',
                null,
                null,
                true
            )
        ));

        $this->assertTrue(is_array(
            $instance::create(
                'clientid',
                'LASTQUARTER',
                null,
                null,
                true
            )
        ));

        $this->assertTrue(is_array(
            $instance::create(
                'clientid',
                'QUARTERTODATE',
                null,
                null,
                true
            )
        ));

        $this->assertTrue(is_array(
            $instance::create(
                'clientid',
                'LASTMONTH',
                null,
                null,
                true
            )
        ));

        $this->assertTrue(is_array(
            $instance::create(
                'clientid',
                'LASTYEAR',
                null,
                null,
                true
            )
        ));

        $this->assertTrue(is_array(
            $instance::create(
                'clientid',
                'MONTHTODATE',
                null,
                null,
                true
            )
        ));

        $this->assertTrue(is_array(
            $instance::create(
                'clientid',
                'YETSERDAY',
                null,
                null,
                true
            )
        ));

        $this->assertTrue(is_array(
            $instance::create(
                'clientid',
                'LASTWEEK',
                null,
                null,
                true
            )
        ));

        $this->assertTrue(is_array(
            $instance::create(
                'clientid',
                'WEEKTODATE',
                null,
                null,
                true
            )
        ));

        $this->assertFalse(
            $instance::create(
                'clientid',
                'UNKNOWN',
                null,
                null
            )
        );

        $this->assertFalse(
            $instance::create(
                'clientid',
                array(),
                null,
                null
            )
        );
    }
}