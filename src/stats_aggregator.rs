use std::{
    collections::HashMap,
    fmt::Display,
    net::Ipv4Addr,
    ops::{Add, AddAssign, Div},
};

use itertools::Itertools;
use ringbuf::{
    traits::{Consumer, Observer, RingBuffer},
    HeapRb,
};
use tracing::Level;

use crate::trace_dbg;

pub struct StatsAggregator {
    /// down, up, local, "other"
    speed_buffer_: HeapRb<Vec<u128>>,
    stat_keys_buffer_: HeapRb<StatKey>,

    stats_buffer: HeapRb<StatsMap>,
    pairs_buffer: HeapRb<PairStatMap>,
    hosts_buffer: HeapRb<HashMap<Ipv4Addr, Speed>>,
    total_speed_buffer: HeapRb<Speed>,
}

impl StatsAggregator {
    fn new() -> Self {
        Self::new_with_window_size(10)
    }

    fn new_with_window_size(window: usize) -> Self {
        Self {
            speed_buffer_: HeapRb::new(window),
            stat_keys_buffer_: HeapRb::new(100),
            stats_buffer: HeapRb::new(window),
            pairs_buffer: HeapRb::new(window),
            hosts_buffer: HeapRb::new(window),
            total_speed_buffer: HeapRb::new(window),
        }
    }

    pub fn tick(&mut self, hash_map: StatsMap) {
        let init = vec![0, 0, 0, 0];
        let sum = hash_map.iter().map(|(k, v)| (&k.direction, v.size)).fold(
            init.clone(),
            |acc, (di, si)| match di {
                Direction::Outgoing => {
                    vec![acc[0] + si, acc[1], acc[2], acc[3]]
                }
                Direction::Incomming => {
                    vec![acc[0], acc[1] + si, acc[2], acc[3]]
                }
                Direction::Local => {
                    vec![acc[0], acc[1], acc[2] + si, acc[3]]
                }
                Direction::None => {
                    vec![acc[0], acc[1], acc[2], acc[3] + si]
                }
            },
        );
        self.speed_buffer_.push_overwrite(sum);
        hash_map.keys().for_each(|k| {
            self.stat_keys_buffer_.push_overwrite(k.clone());
        });

        self.stats_buffer.push_overwrite(hash_map);

        self.update_pairs_stats_buffer();
        self.update_hosts_stats_buffer();
        self.update_total_speed();
    }

    fn update_pairs_stats_buffer(&mut self) {
        self.pairs_buffer.clear();
        self.stats_buffer.iter().for_each(|item| {
            let mut pairs: PairStatMap = Default::default();
            item.iter().for_each(|(k, v)| {
                let (mut src, mut dst) = (k.src_ip, k.dst_ip);
                let is_local = k.direction == Direction::Local;
                if Direction::Incomming == k.direction || (is_local && src > dst) {
                    (src, dst) = (dst, src);
                }
                let pair = IpPair {
                    src_ip: src,
                    dst_ip: dst,
                    is_local,
                };
                let mut speed_pair_to_add: Speed = Default::default();
                match k.direction {
                    Direction::Outgoing => {
                        speed_pair_to_add.output += v.size;
                    }
                    Direction::Incomming => {
                        speed_pair_to_add.input += v.size;
                    }
                    Direction::Local => {
                        if src != k.src_ip {
                            speed_pair_to_add.output += v.size;
                        } else {
                            speed_pair_to_add.input += v.size;
                        }
                    }
                    Direction::None => {
                        let msg = format!("{} {}", src, dst);
                        trace_dbg!(level: Level::ERROR, msg);
                    }
                }
                pairs
                    .entry(pair)
                    .and_modify(|speed_pair| {
                        *speed_pair += speed_pair_to_add;
                    })
                    .or_insert(speed_pair_to_add);
            });
            self.pairs_buffer.push_overwrite(pairs);
        });
    }

    pub fn speed_per_host(&self) -> HashMap<Ipv4Addr, Speed> {
        let mut map_sn: HashMap<Ipv4Addr, (Speed, u8)> = Default::default();
        let mut map: HashMap<Ipv4Addr, Speed> = Default::default();

        self.hosts_buffer.iter().for_each(|pair| {
            pair.iter().for_each(|(ip, speed)| {
                map_sn
                    .entry(*ip)
                    .and_modify(|(s, n)| {
                        *s += *speed;
                        *n += 1
                    })
                    .or_insert((*speed, 1));
            });
        });
        map_sn.iter().for_each(|(ip, (speed, n))| {
            map.insert(*ip, *speed / (*n as u128));
        });
        map
    }

    pub fn speed_str(&self) -> String {
        if self.total_speed_buffer.is_empty() {
            return "".to_string();
        }
        let avg: Speed = self.total_speed_buffer.iter().fold(
            Speed {
                output: 0,
                input: 0,
            },
            |a, b| a + *b,
        ) / (self.total_speed_buffer.occupied_len() as u128);
        avg.to_string()
    }

    pub fn connections_strs(&self) -> Vec<String> {
        let mut pairs_avg: HashMap<IpPair, (Speed, u8)> = Default::default();
        self.pairs_buffer.iter().for_each(|map| {
            map.iter().for_each(|(pair, speed)| {
                pairs_avg
                    .entry(pair.to_owned())
                    .and_modify(|pair_and_num| {
                        pair_and_num.0 += *speed;
                        pair_and_num.1 += 1;
                    })
                    .or_insert((*speed, 1));
            });
        });
        let mut keys = pairs_avg.keys().collect_vec();
        keys.sort();
        keys.iter()
            .map(|a| {
                let (speeds_sum, n) = pairs_avg.get(a).unwrap();
                let speed_avg = *speeds_sum / *n as u128;
                let sep = match (speed_avg.input != 0, speed_avg.output != 0) {
                    (true, true) => "<->",
                    (true, false) => "-->",
                    (false, true) => "<--",
                    (false, false) => "---",
                };
                format!("{} {} {} \t ({})", a.src_ip, sep, a.dst_ip, speed_avg)
            })
            .collect()
    }

    fn update_hosts_stats_buffer(&mut self) {
        self.hosts_buffer.clear();
        self.pairs_buffer.iter().for_each(|pairs| {
            let mut hosts_pair: HashMap<Ipv4Addr, Speed> = Default::default();
            pairs
                .iter()
                .filter(|(pair, _)| !pair.is_local)
                .for_each(|(pair, speed)| {
                    hosts_pair
                        .entry(pair.src_ip)
                        .and_modify(|sp| {
                            *sp += *speed;
                        })
                        .or_insert(*speed);
                });
            self.hosts_buffer.push_overwrite(hosts_pair);
        });
    }

    fn update_total_speed(&mut self) {
        self.total_speed_buffer.clear();
        self.hosts_buffer.iter().for_each(|per_host| {
            let mut speed_sum: Speed = Default::default();
            per_host.iter().for_each(|(_adr, speed)| {
                speed_sum += *speed;
            });
            self.total_speed_buffer.push_overwrite(speed_sum);
        });
    }
}

impl Default for StatsAggregator {
    fn default() -> Self {
        Self::new()
    }
}

pub type StatsMap = HashMap<StatKey, StatValues>;

#[derive(Debug, Clone)]
pub struct StatItem {
    pub key: StatKey,
    pub value: StatValues,
}

type PairStatMap = HashMap<IpPair, Speed>;
#[derive(Hash, PartialEq, Eq, Debug, Clone, PartialOrd, Ord)]
struct IpPair {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    is_local: bool,
}
#[derive(Default, Debug, Clone, Copy)]
pub struct Speed {
    output: u128,
    input: u128,
}

impl Add for Speed {
    type Output = Speed;

    fn add(self, rhs: Self) -> Self::Output {
        Speed {
            input: self.input + rhs.input,
            output: self.output + rhs.output,
        }
    }
}

impl AddAssign for Speed {
    fn add_assign(&mut self, rhs: Self) {
        self.input += rhs.input;
        self.output += rhs.output;
    }
}
impl Div<u128> for Speed {
    type Output = Speed;

    fn div(self, rhs: u128) -> Self::Output {
        Speed {
            input: self.input / rhs,
            output: self.output / rhs,
        }
    }
}
impl Display for Speed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "↓ {} | ↑ {}",
            format_size(self.input),
            format_size(self.output)
        )
    }
}
impl Speed {
    pub fn to_string_input(&self) -> String {
        format_size(self.input)
    }
    pub fn to_string_output(&self) -> String {
        format_size(self.output)
    }
}

#[derive(Hash, PartialEq, Eq, Debug, Clone)]
pub struct StatKey {
    pub src_port: u16,
    pub sdt_port: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub direction: Direction,
}

#[derive(Hash, PartialEq, Eq, Debug, Clone)]
pub enum Direction {
    None,
    Outgoing,
    Incomming,
    Local,
}

#[derive(Debug, Clone)]
pub struct StatValues {
    pub size: u128,
}

const B_1024: f64 = 1024f64;
fn format_size(bits: u128) -> String {
    let bits = f64::from(bits as u32);
    let kbits = if bits < B_1024 {
        return format!("{:.2} Bit/s", bits);
    } else {
        bits / B_1024
    };

    let mbits = if kbits < B_1024 {
        return format!("{:.2} Kib/s", kbits);
    } else {
        kbits / B_1024
    };

    format!("{:.2} Mib/s", mbits)
}
