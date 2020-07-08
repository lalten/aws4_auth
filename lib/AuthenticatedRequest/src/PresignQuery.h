#pragma once

#include <etl/cstring.h>
#include <etl/string_view.h>

#include "Signature.h"

class PresignQuery {
    static etl::string<1024> get(const Signature &sig);
};
