#include "PKConfig.hpp"
#include "Listener.hpp"

namespace Rknockd
{

PKListener::PKListener(const PKConfig& c, bool verbose_logging) THROW((IOException, NFQ::NfqException))
: Listener(c, "/proc/"REMAP_PROC_FILE, verbose_logging), config(c), hostTable(), hostTableGC(hostTable, verbose_logging)
{
}


} // namespace Rknockd
