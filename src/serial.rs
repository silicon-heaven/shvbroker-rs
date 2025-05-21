use std::time::Duration;
use futures::io::BufWriter;
use log::{error, info};
use serialport::SerialPort;
use shvrpc::framerw::{FrameReader, FrameWriter};
use shvrpc::rpcmessage::PeerId;
use shvrpc::serialrw::{SerialFrameReader, SerialFrameWriter};
use smol::{Unblock};
use smol::channel::Sender;
use smol::io::BufReader;
use crate::brokerimpl::{BrokerCommand};
use crate::config::AzureConfig;
use crate::peer::server_peer_loop;

fn open_serial(port_name: &str) -> shvrpc::Result<(Box<dyn SerialPort>, Box<dyn SerialPort>)> {
    info!("Opening serial port: {}", port_name);
    let port = serialport::new(port_name, 115200)
        .data_bits(serialport::DataBits::Eight)
        .stop_bits(serialport::StopBits::One)
        .parity(serialport::Parity::None)
        // serial port should never timeout,
        // timeout on serial breaks reader loop
        .timeout(Duration::from_secs(60 * 60 *24 * 365 * 100))
        .open()?;

    // Clone the port
    let port_clone = port.try_clone()?;
    info!("open serial port OK");
    Ok((port, port_clone))
}

pub(crate) async fn try_serial_peer_loop(peer_id: PeerId, broker_writer: Sender<BrokerCommand>, port_name: String, azure_config: Option<AzureConfig>) -> shvrpc::Result<()> {
    info!("Entering serial peer loop client ID: {peer_id}, port: {port_name}.");
    match serial_peer_loop(peer_id, broker_writer.clone(), &port_name, azure_config).await {
        Ok(_) => {
            info!("Serial peer loop exit OK, peer id: {peer_id}");
        }
        Err(e) => {
            error!("Serial peer loop exit ERROR, peer id: {peer_id}, error: {e}");
        }
    }
    broker_writer.send(BrokerCommand::PeerGone { peer_id }).await?;
    Ok(())
}
async fn serial_peer_loop(peer_id: PeerId, broker_writer: Sender<BrokerCommand>, port_name: &str, azure_config: Option<AzureConfig>) -> shvrpc::Result<()> {
    let (frame_reader, frame_writer) = create_serial_frame_reader_writer(port_name)?;
    server_peer_loop(peer_id, broker_writer, frame_reader, frame_writer, azure_config).await
}

pub(crate) fn create_serial_frame_reader_writer(port_name: &str) -> shvrpc::Result<(impl FrameReader + use<>, impl FrameWriter + use<>)> {
    let (rd, wr) = open_serial(port_name)?;
    let serial_reader = Unblock::new(rd);
    let serial_writer = Unblock::new(wr);

    let brd = BufReader::new(serial_reader);
    let bwr = BufWriter::new(serial_writer);

    let frame_reader = SerialFrameReader::new(brd).with_crc_check(true);
    let frame_writer = SerialFrameWriter::new(bwr).with_crc_check(true);

    Ok((frame_reader, frame_writer))
}
