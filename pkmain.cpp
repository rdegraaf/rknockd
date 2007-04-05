#include <iostream>
#include <iomanip>
#include <cstdlib>
#include "Config.hpp"
#include <boost/thread/thread.hpp>
#include "NFQ.hpp"
#include "Listener.hpp"
#include "PKConfig.hpp"

namespace Rknockd
{

class KnockListener : public Listener
{
  public:
    KnockListener(const Config& c)
    : Listener(c)
    {}
    ~KnockListener()
    {}
    void operator() ()
    {
        try
        {
            NFQ::NfqSocket sock(0); //config.getNfQueueNum());
            sock.setCopyMode(NFQ::NfqSocket::PACKET);
            
            try
            {
                NFQ::NfqPacket* packet = sock.recvPacket();
                
                printPacketInfo(packet, std::cout);

                packet->setVerdict(NFQ::NfqPacket::ACCEPT);
                sock.sendResponse(packet);
                delete packet;
            }
            catch (NFQ::NfqException& e)
            {
                std::cout << "Error processing packet: " << e.what() << std::endl;
            }
        
            try
            {
                sock.close();
            }
            catch (NFQ::NfqException& e)
            {
                std::cout << "Error disconnecting from NFQUEUE: " << e.what() << std::endl;
            }
        }
        catch (NFQ::NfqException& e)
        {
            std::cout << "Error connecting to NFQUEUE: " << e.what() << std::endl;
        }
    }
  private:

};


} // namespace Rknockd




int
main(const int argc, const char** argv)
{
    std::string config_file = "pkconfig.xml";
    
    try
    {
        // load configuration
        Rknockd::PKConfig config(config_file);
#ifdef DEBUG
        config.printConfig(std::cout);
#endif
        
        try
        {
            // start up threads
            Rknockd::KnockListener k(config);
            boost::thread listener(k);

            // clean up
            listener.join();
        }
        catch (const boost::thread_resource_error& e)
        {
            std::cerr << "Error starting threads: " << e.what() << std::endl;
            std::exit(EXIT_FAILURE);
        }
    }
    catch (const Rknockd::ConfigException& e)
    {
        std::cerr <<  "Error loading configuration file: " << e.what() << std::endl;
        std::exit(EXIT_FAILURE);
    }
    
    return EXIT_SUCCESS;
}

