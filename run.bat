python3 ken1key_ipa_signer.py \
  --ipa input.ipa \
  --out signed.ipa \
  --p12 certs/ken1key.p12 \
  --p12-password ken1pass \
  --mobileprovision certs/ken1key.mobileprovision \
  --bundle-id com.kenen.ikiowk \
  --debug \
  --verbose
