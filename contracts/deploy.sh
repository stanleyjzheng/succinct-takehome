forge create \
    --rpc-url https://sepolia.base.org \
    --etherscan-api-key $BASESCAN_API_KEY \
    --verify --chain-id 84532 \
    --private-key $BASE_SEPOLIA_PRIVATE_KEY
    src/SP1AggregationVerifier.sol:SP1AggregationVerifier \
    --constructor-args "0x3B6041173B80E77f038f3F2C0f9744f04837185e" "0x00297f566c27356039e0cb03958b15919cfcfd3b88643827d3b9b884c3714e96"
