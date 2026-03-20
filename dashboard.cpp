// src/dashboard.cpp
#include "dashboard.h"
#include <cmath>
#include <cstdio>

// Environmental model constants
static constexpr double kKgCo2PerTbPerYear   = 40.0;   // ~40 kg CO2e / TB / year
static constexpr double kGCo2PerKmCar        = 120.0;  // g CO2 / km (mid-range petrol)
static constexpr double kLedBulbWatts        = 9.0;    // typical LED bulb wattage
static constexpr double kKwhPerKgCo2         = 2.5;    // avg EU grid, 2024 estimate
static constexpr double kBytesPerTb          = 1099511627776.0;
static constexpr double kBytesPerGb          = 1073741824.0;

SustainabilityDashboard SustainabilityDashboard::FromBytes(uint64_t bytes)
{
    SustainabilityDashboard d;
    d.bytes_wiped   = bytes;
    d.tb_wiped      = static_cast<double>(bytes) / kBytesPerTb;
    d.gb_wiped      = static_cast<double>(bytes) / kBytesPerGb;

    d.estimated_co2_kg_per_year = d.tb_wiped * kKgCo2PerTbPerYear;

    double kwh_saved = d.estimated_co2_kg_per_year * kKwhPerKgCo2;
    d.equivalent_car_km         = (d.estimated_co2_kg_per_year * 1000.0) / kGCo2PerKmCar;
    d.equivalent_led_bulb_hours = (kwh_saved * 1000.0) / kLedBulbWatts;

    d.model_disclaimer =
        "DISCLAIMER: CO2 estimates are approximate and model-based. "
        "Model assumes ~40 kg CO2e per TB of storage per year, "
        "based on average data center energy mix. "
        "Actual savings depend on regional energy sources, hardware generation, "
        "and utilization patterns. Values should not be cited as precise measurements.";

    return d;
}

SustainabilityDashboard SustainabilityDashboard::FromCertificate(
    const WipeCertificate& cert)
{
    auto d = FromBytes(cert.bytes_wiped);
    d.certificate_id = cert.id;
    return d;
}

void SustainabilityDashboard::Print() const
{
    printf("\n");
    printf("╔══════════════════════════════════════════╗\n");
    printf("║     SecureWipe Sustainability Dashboard   ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");

    if (!certificate_id.empty()) {
        printf("  Certificate: %s\n", certificate_id.c_str());
    }

    printf("  ┌─────────────────────────────────────────┐\n");
    printf("  │  Storage wiped                          │\n");
    printf("  │  %.2f GB  (%.4f TB)                 │\n", gb_wiped, tb_wiped);
    printf("  └─────────────────────────────────────────┘\n\n");

    printf("  Estimated environmental impact (1-year model):\n");
    printf("  ─────────────────────────────────────────────\n");

    if (estimated_co2_kg_per_year < 0.001) {
        printf("  CO2 savings  : < 0.001 kg  (storage too small for significant impact)\n");
    } else if (estimated_co2_kg_per_year < 1.0) {
        printf("  CO2 savings  : ~%.3f kg CO2e/year\n", estimated_co2_kg_per_year);
    } else {
        printf("  CO2 savings  : ~%.2f kg CO2e/year\n", estimated_co2_kg_per_year);
    }

    if (equivalent_car_km >= 1.0) {
        printf("  Equivalent to: avoiding %.1f km of car travel\n", equivalent_car_km);
    }

    if (equivalent_led_bulb_hours >= 1.0) {
        printf("  Equivalent to: running a 9W LED bulb for %.0f hours\n",
               equivalent_led_bulb_hours);
    }

    printf("\n  WARNING: %s\n\n", model_disclaimer.c_str());
}
