use super::budget::*;
use super::protected::*;

#[tokio::test]
async fn reply_backing_moves_to_writer_and_stays_charged_through_flush() {
    use tokio::io::AsyncReadExt;
    let process = ChannelBudget::new();
    let instance = process.instance();
    let unit = instance.unit();
    let link = instance.link();
    let general = unit.reserve(Claim { bytes: UNIT_BYTES - REPLY_BYTES, ..Claim::default() }, None).unwrap();
    let mut inspection = ReplyStorage::new(&unit).unwrap();
    inspection.output_mut()[24..29].copy_from_slice(b"reply");
    let write = inspection.into_write(24..29, &link).unwrap();
    assert_eq!(unit.used().bytes, UNIT_BYTES - REPLY_BYTES + 6);
    let (mut sender, mut reader) = tokio::io::duplex(2);
    let run = tokio::spawn(async move { write.write_ndjson(&mut sender).await });
    tokio::task::yield_now().await;
    assert_eq!(unit.used().messages, 1, "the blocked writer owns its cell");
    let mut bytes = [0; 6];
    reader.read_exact(&mut bytes).await.unwrap();
    run.await.unwrap().unwrap();
    assert_eq!(&bytes, b"reply\n");
    drop(general);
    assert_eq!(process.used(), Claim::default());
}

#[test]
fn invalid_reply_range_and_foreign_destination_publish_nothing() {
    let process = ChannelBudget::new();
    let instance = process.instance();
    let unit = instance.unit();
    let other = process.instance().link();
    let inspection = ReplyStorage::new(&unit).unwrap();
    assert!(inspection.into_write(0..1, &other).is_err());
    assert_eq!(process.used(), Claim::default());
    let inspection = ReplyStorage::new(&unit).unwrap();
    assert!(inspection.into_write(0..OUTPUT_BYTES + 1, &instance.link()).is_err());
    assert_eq!(process.used(), Claim::default());
}

#[test]
fn maximum_reply_fits_reserved_native_envelope_at_general_saturation() {
    let process = ChannelBudget::new();
    let instance = process.instance();
    let unit = instance.unit();
    let general = unit.reserve(Claim { bytes: UNIT_BYTES - REPLY_BYTES, ..Claim::default() }, None).unwrap();
    let inspection = ReplyStorage::new(&unit).unwrap();
    assert_eq!(inspection.output().len(), OUTPUT_BYTES);
    let writer = inspection.into_write(24..OUTPUT_BYTES, &instance.link()).unwrap();
    assert_eq!(writer.len(), super::frame::MAX_MESSAGE);
    assert!(ReplyStorage::new(&unit).is_err(), "queued reply retains the protected bytes");
    drop((writer, general));
    assert_eq!(process.used(), Claim::default());
}
