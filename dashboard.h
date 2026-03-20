#pragma once
// include/dashboard.h  —  Sustainability dashboard

#include "common.h"
#include "certificate.h"
#include <string>

struct SustainabilityDashboard {
    uint64_t bytes_wiped                 = 0;
    double   gb_wiped                    = 0.0;
    double   tb_wiped                    = 0.0;
    double   estimated_co2_kg_per_year   = 0.0;
    double   equivalent_car_km          = 0.0;
    double   equivalent_led_bulb_hours  = 0.0;
    std::string model_disclaimer;
    std::string certificate_id;

    static SustainabilityDashboard FromBytes(uint64_t bytes);
    static SustainabilityDashboard FromCertificate(const WipeCertificate& cert);

    void Print() const;
};
