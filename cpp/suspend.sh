#!/bin/bash
$@ &
PID=$!
sleep .001
kill -STOP $PID
echo $PID
wait $PID
