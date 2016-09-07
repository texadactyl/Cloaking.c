PASSWORD=password
LOG=run.log
#VERBOSE=-v
DATA=../data

cloak $VERBOSE $PASSWORD $DATA/aa $DATA/bb.tiff 2>&1 | tee $LOG
if [ ${PIPESTATUS[0]} -ne 0 ]; then
	exit 86
fi
echo "========================================================" 2>&1 | tee -a $LOG
uncloak $VERBOSE $PASSWORD $DATA/bb.tiff $DATA/cc 2>&1 | tee -a $LOG
if [ ${PIPESTATUS[0]} -ne 0 ]; then
	exit 86
fi
echo "========================================================" 
cmp -l $DATA/aa $DATA/cc
if [ $? -eq 0 ]; then
	echo "cmp reported SUCCESS"
fi
