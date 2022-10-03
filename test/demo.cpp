#include <memory>
#include <ravl/ravl.h>
#include <ravl/sev_snp.h>
#include <string>

using namespace ravl;

std::string sev_snp_quote = R"({
  "source": "sevsnp",
  "evidence": "AgAAAAIAAAAfAAMAAAAAAAEAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAACAAAAAAAGXQEAAAAAAAAAAAAAAAAAAAAIebqLxUFNeClkL/A6LBA8wU4yNcH9toPXIilkiXu9pAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7egmiApOGkGJipaBDvsJ8gcFE6uzVeiWUlZM0Y8dQ6egMdH/VEkNvWFofeEBtm7Rq2zP6m6MnGIzsaRjHP1kQOz5EGlLNNfpLgI2c4dYgx7Jd7YxN5Mm9yaAsdvoZmL6aQJIUWkv0us4lpcXm8svL3wLfrV2ayYju9fliLMU7TsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADBaTMJli6XmTLdGMhIQwna+cvhFRW0mlE5lSnZ/syuff//////////////////////////////////////////AgAAAAAABl0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACC56n0RuAHUmaVpDq9HgesfXJi+0SshmghSEuJ6H2NMYxNevZOsxVKp16LCwJsTG/PQAiSSeX05Y4Xc0VQr0bmAgAAAAAABl0BMwEAATMBAAIAAAAAAAZdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIr/RXe35MB1ZUdct19i1+fYDJlXAah5pPGuZBMdsHAVtuxhUfKg6mgLLCpa3cLC4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMW3WN0MtbBffLaVNsNlsnVTrw0qC/qrQdniBfK345BiyIicVCgR6/Z5YZ6CmTpByAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
})";

int main()
{
  /// SNIPPET_START: BASIC_USAGE
  auto att = parse_attestation(sev_snp_quote);
  std::shared_ptr<Claims> claims = verify(att);
  auto sc = Claims::get<sev_snp::Claims>(claims);

  // Check, e.g., sc->measurement
  /// SNIPPET_END: BASIC_USAGE

  return 0;
}