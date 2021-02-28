/**
 * @brief - implements the packet generator
 *
 * @author Devendra Naga (devendra.aaru@outlook.com) 2020-present All rights reserved
 */
#include <thread>
#include <auto_idps.h>

namespace auto_os::idps {

std::shared_ptr<auto_os::lib::logger> log;
static auto_os::lib::event_manager *evt_mgr;

#define PKT_GEN_CONFIG "pkt_gen.json"

/**
 * @brief - packet gtnertor configuration
 */
struct pkt_generator_config {
    std::string sim_interface;
    bool enable_pcap_replay;
    std::string pcap_filepath;
    int pcap_replay_intvl_msec;

    ~pkt_generator_config() { }
    static pkt_generator_config *instance() {
        static pkt_generator_config config;
        return &config;
    }

    int parse(const std::string config);
    private:
        explicit pkt_generator_config() { }
};

/**
 * @brief - packet generator
 */
class pkt_generator {
    public:
        explicit pkt_generator();
        ~pkt_generator();

        void start();

    private:
        std::unique_ptr<auto_os::lib::pcap_op> pcap_;
        void pcap_replay_timer();
        bool end_of_pcap_replay_;
        std::unique_ptr<auto_os::lib::raw_socket> eth_;
};

int pkt_generator_config::parse(const std::string config)
{
    Json::Value root;
    std::ifstream conf(config, std::ifstream::binary);

    conf >> root;

    sim_interface = root["simulation_intf"].asString();
    enable_pcap_replay = root["enable_pcap_replay"].asBool();
    pcap_filepath = root["pcap_file_path"].asString();
    pcap_replay_intvl_msec = root["pcap_replay_intvl_msec"].asInt();

    return 0;
}

pkt_generator::pkt_generator()
{
    // getting log instance
    log = auto_os::lib::logger_factory::Instance()->create(
                        auto_os::lib::logging_type::console_logging);

    // get an instance of event manager
    evt_mgr = auto_os::lib::event_manager::instance();

    // parse the configuration
    pkt_generator_config *conf = pkt_generator_config::instance();
    if (conf->parse(PKT_GEN_CONFIG)) {
        throw std::runtime_error("failed to parse configuration\n");
    }

    // create raw socket
    eth_ = std::make_unique<auto_os::lib::raw_socket>(conf->sim_interface, 0x0);

    end_of_pcap_replay_ = false;

    //
    // enable pap replay
    //
    if (conf->enable_pcap_replay) {
        // get an instance of pcap file
        pcap_ = std::make_unique<auto_os::lib::pcap_op>(conf->pcap_filepath, auto_os::lib::pcap_op_type::read_op);

        // set timer and trigger it peridically
        auto pcap_rep_cb = std::bind(&pkt_generator::pcap_replay_timer, this);

        log->info("pkt_gen: pcap replay callback set\n");

        evt_mgr->create_timer_event(0, conf->pcap_replay_intvl_msec * 1000, pcap_rep_cb);
    }

    log->info("pkt_gen: pcap replay timer created\n");
}

void pkt_generator::pcap_replay_timer()
{
    auto_os::lib::pcap_rechdr_t rec;
    uint8_t pkt[2048];
    int ret;

    if (end_of_pcap_replay_) {
        log->info("pkt_gen: replay complete\n");
        return;
    }

    // read one packet
    ret = pcap_->read_record(rec, pkt, sizeof(pkt));
    if (ret < 0) {
        log->info("pkt_gen: replay ended\n");
        end_of_pcap_replay_ = true;
        return;
    }

    static int count = 1;

    log->debug("pkt_gen: play [%d]\n", count ++);

    uint8_t mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    ret = eth_->send_msg(mac, pkt, ret);
}

pkt_generator::~pkt_generator()
{
}

void pkt_generator::start()
{
    evt_mgr->start();
}

}

int main()
{
    auto_os::idps::pkt_generator pkt;

    pkt.start();
    return 0;
}


