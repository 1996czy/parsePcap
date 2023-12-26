extern crate pcap;
extern crate chrono;
use chrono::{DateTime, Utc, Duration, Local};
use pcap::Capture;


// calculate data day's total seconds till given time
fn day_sec(time: String) -> f32
{
    return ((&time[0..2]).parse::<f32>().unwrap() * 3600.0
     + (&time[2..4]).parse::<f32>().unwrap() * 60.0
      + (&time[4..6]).parse::<f32>().unwrap()
       + (&time[6..]).parse::<f32>().unwrap() / ((10_i32.pow((&time[6..]).len() as u32)) as f32))
}


// print required results for the test
fn print_data(packet_ts: String, data_body: String)
{
    println!(
        "{packet_ts} {accept_time} {issue_code} {bq5}@{bp5} {bq4}@{bp4} {bq3}@{bp3} {bq2}@{bp2} {bq1}@{bp1} {aq1}@{ap1} {aq2}@{ap2} {aq3}@{ap3} {aq4}@{ap4} {aq5}@{ap5}",
        packet_ts=packet_ts,
        issue_code=&data_body[0..12],
        bp1=&data_body[24..29],
        bq1=&data_body[29..36],
        bp2=&data_body[36..41],
        bq2=&data_body[41..48],
        bp3=&data_body[48..53],
        bq3=&data_body[53..60],
        bp4=&data_body[60..65],
        bq4=&data_body[65..72],
        bp5=&data_body[72..77],
        bq5=&data_body[77..84],
        ap1=&data_body[91..96],
        aq1=&data_body[96..103],
        ap2=&data_body[103..108],
        aq2=&data_body[108..115],
        ap3=&data_body[115..120],
        aq3=&data_body[120..127],
        ap4=&data_body[127..132],
        aq4=&data_body[132..139],
        ap5=&data_body[139..144],
        aq5=&data_body[144..151],
        accept_time=&data_body[201..209]
    );
}


fn main()
{
    // println!("Program start at {:?}", Local::now());
    // accept params from command line
    let args: Vec<String> = std::env::args().collect();
    let file: &String = &args[1];
    let sort: bool;
    match args.len()
    {
        3 => match &args[2] as &str 
        {
            "-r" => sort = true,
            _ => sort=false
        },

        _ => sort=false
    }

    // read pcap file by line
    let mut cap = Capture::from_file(file).unwrap();
    cap.filter("port 15515 or port 15516", true).expect("cannot filter port");

    // string to receive packet elements
    let mut data_head: String = String::new();
    let mut data_body: String = String::new();
    // assume the max difference of packet time and accept time is less than 3 seconds.
    let assume_max_lag: f32 = 3.0;
    let mut delete_list: Vec<String> = Vec::new();
    let mut data_buffer: std::collections::BTreeMap<String, Vec<(String, String)>> = std::collections::BTreeMap::new();
    
    while let Ok(packet) = cap.next_packet()
    {
        let tv_sec: i64 = packet.header.ts.tv_sec as i64;
        let tv_usec: u32 = (packet.header.ts.tv_usec) as u32;
        let packet_ts: String = format!("{}.{}", tv_sec, tv_usec);

        let data = packet.data;
        for sub_data in data
        {
            if *sub_data > 31 && (*sub_data).is_ascii()
            {
                if data_head.ends_with("B6034")
                {
                    // collect market data
                    data_body.push(char::from(*sub_data));
                }
                else
                {
                    // look for beginning of market data
                    data_head.push(char::from(*sub_data));
                }
            }
        }

        // this line got market data
        if data_body.len() > 0
        {
            if sort
            {
                // change to Japan Timezone
                let dt = (DateTime::<Utc>::from_timestamp(tv_sec, (((tv_usec) as f32) / 10_f32.powf(tv_usec.to_string().len() as f32) * 1000000000.0) as u32)).unwrap() + Duration::hours(9);
                // calculate the seconds since today
                let packet_time: f32 = day_sec((dt.format("%H%M%S%f")).to_string());
                let accept_time: f32 = day_sec((&data_body[201..209]).to_string());
                let accept_time_str: String = accept_time.to_string();

                // initialize the pair if first met
                if !data_buffer.contains_key(&accept_time_str)
                {
                    data_buffer.insert((*accept_time_str).to_string(), Vec::<(String, String)>::new());
                }

                // append the data to map
                data_buffer.get_mut(&accept_time_str).unwrap().push(((*packet_ts).to_string(), (*data_body).to_string()));

                // iter the map and print data with accept time out of 3 seconds
                for (acct, sub_vec) in data_buffer.iter()
                {
                    if packet_time - acct.parse::<f32>().unwrap() <= assume_max_lag
                    {
                        break;
                    }
                    else
                    {
                        delete_list.push(acct.to_string());
                        for sub_data in sub_vec
                        {
                            print_data(sub_data.0.to_string(), sub_data.1.to_string());
                        }
                    }
                }
                // delete which has been print
                for acct in &delete_list
                {
                    data_buffer.remove(acct);
                }
                delete_list.clear();
            }
            else
            {
                // if no sort requirement, just print
                print_data(packet_ts, data_body.clone());
            }
        }
        data_head.clear();
        data_body.clear();
    }
    
    // print the last few of data within 3 seconds
    if sort
    {
        for (acct, sub_vec) in data_buffer.iter()
        {
            for sub_data in sub_vec
            {
                print_data(sub_data.0.to_string(), sub_data.1.to_string());
            }
        }
    }
    // println!("Program end at {:?}", Local::now());
}
