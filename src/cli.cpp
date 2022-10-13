#include <CLI11/CLI11.hpp>
#include <fstream>
#include <iostream>
#include <ravl/options.h>
#include <ravl/ravl.h>
#include <sstream>

int main(int argc, const char** argv)
{
  CLI::App app{"ravl"};

  try
  {
    ravl::Options options = {.verbosity = 1};

    app.add_option("-v", options.verbosity, "Verbosity");
    app.add_flag(
      "-f", options.fresh_endorsements, "Force download of fresh endorsements");
    app.add_flag(
      "-r",
      options.fresh_root_ca_certificate,
      "Force download of fresh root certificate");
    app.add_flag(
      "-e",
      options.certificate_verification.ignore_time,
      "Ignore expiry time of certificates");

    app.allow_config_extras(true);

    app.parse(argc, argv);

    for (auto f : app.remaining())
    {
      std::ifstream is(f);
      if (!is.good())
      {
        std::cout << "Warning: error opening '" << f << "', skipping."
                  << std::endl;
        continue;
      }

      std::stringstream sstr;
      sstr << is.rdbuf();
      auto attestation = ravl::parse_attestation(sstr.str());

      try
      {
        auto claims = verify_synchronized(attestation, options);
      }
      catch (const std::exception& ex)
      {
        std::cout << "Error: " << ex.what() << std::endl;
      }
    }
  }
  catch (const CLI::ParseError& e)
  {
    return app.exit(e);
  }
  catch (const std::exception& ex)
  {
    std::cout << "Exception: " << ex.what() << std::endl;
    return 2;
  }
  catch (...)
  {
    std::cout << "Caught unknown exception" << std::endl;
    return 2;
  }

  return 0;
}