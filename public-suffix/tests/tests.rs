// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! These tests are transliterated from list_test.go. Some of the tests from
//! list_test.go were made unit tests inside lib.rs.

use public_suffix::*;

static TEST_CASES: &[(&str, &str)] = &[
    // Empty string.
    ("", ""),
    // The .ao rules are:
    // ao
    // ed.ao
    // gv.ao
    // og.ao
    // co.ao
    // pb.ao
    // it.ao
    ("ao", "ao"),
    ("www.ao", "ao"),
    ("pb.ao", "pb.ao"),
    ("www.pb.ao", "pb.ao"),
    ("www.xxx.yyy.zzz.pb.ao", "pb.ao"),
    // The .ar rules are:
    // ar
    // com.ar
    // edu.ar
    // gob.ar
    // gov.ar
    // int.ar
    // mil.ar
    // net.ar
    // org.ar
    // tur.ar
    // blogspot.com.ar (in the PRIVATE DOMAIN section).
    ("ar", "ar"),
    ("www.ar", "ar"),
    ("nic.ar", "ar"),
    ("www.nic.ar", "ar"),
    ("com.ar", "com.ar"),
    ("www.com.ar", "com.ar"),
    ("blogspot.com.ar", "blogspot.com.ar"), // PRIVATE DOMAIN.
    ("www.blogspot.com.ar", "blogspot.com.ar"), // PRIVATE DOMAIN.
    ("www.xxx.yyy.zzz.blogspot.com.ar", "blogspot.com.ar"), // PRIVATE DOMAIN.
    ("logspot.com.ar", "com.ar"),
    ("zlogspot.com.ar", "com.ar"),
    ("zblogspot.com.ar", "com.ar"),
    // The .arpa rules are:
    // arpa
    // e164.arpa
    // in-addr.arpa
    // ip6.arpa
    // iris.arpa
    // uri.arpa
    // urn.arpa
    ("arpa", "arpa"),
    ("www.arpa", "arpa"),
    ("urn.arpa", "urn.arpa"),
    ("www.urn.arpa", "urn.arpa"),
    ("www.xxx.yyy.zzz.urn.arpa", "urn.arpa"),
    // The relevant {kobe,kyoto}.jp rules are:
    // jp
    // *.kobe.jp
    // !city.kobe.jp
    // kyoto.jp
    // ide.kyoto.jp
    ("jp", "jp"),
    ("kobe.jp", "jp"),
    ("c.kobe.jp", "c.kobe.jp"),
    ("b.c.kobe.jp", "c.kobe.jp"),
    ("a.b.c.kobe.jp", "c.kobe.jp"),
    ("city.kobe.jp", "kobe.jp"),
    ("www.city.kobe.jp", "kobe.jp"),
    ("kyoto.jp", "kyoto.jp"),
    ("test.kyoto.jp", "kyoto.jp"),
    ("ide.kyoto.jp", "ide.kyoto.jp"),
    ("b.ide.kyoto.jp", "ide.kyoto.jp"),
    ("a.b.ide.kyoto.jp", "ide.kyoto.jp"),
    // The .tw rules are:
    // tw
    // edu.tw
    // gov.tw
    // mil.tw
    // com.tw
    // net.tw
    // org.tw
    // idv.tw
    // game.tw
    // ebiz.tw
    // club.tw
    // 網路.tw (xn--zf0ao64a.tw)
    // 組織.tw (xn--uc0atv.tw)
    // 商業.tw (xn--czrw28b.tw)
    // blogspot.tw
    ("tw", "tw"),
    ("aaa.tw", "tw"),
    ("www.aaa.tw", "tw"),
    ("xn--czrw28b.aaa.tw", "tw"),
    ("edu.tw", "edu.tw"),
    ("www.edu.tw", "edu.tw"),
    ("xn--czrw28b.edu.tw", "edu.tw"),
    ("xn--czrw28b.tw", "xn--czrw28b.tw"),
    ("www.xn--czrw28b.tw", "xn--czrw28b.tw"),
    ("xn--uc0atv.xn--czrw28b.tw", "xn--czrw28b.tw"),
    ("xn--kpry57d.tw", "tw"),
    // The .uk rules are:
    // uk
    // ac.uk
    // co.uk
    // gov.uk
    // ltd.uk
    // me.uk
    // net.uk
    // nhs.uk
    // org.uk
    // plc.uk
    // police.uk
    // *.sch.uk
    // blogspot.co.uk (in the PRIVATE DOMAIN section).
    ("uk", "uk"),
    ("aaa.uk", "uk"),
    ("www.aaa.uk", "uk"),
    ("mod.uk", "uk"),
    ("www.mod.uk", "uk"),
    ("sch.uk", "uk"),
    ("mod.sch.uk", "mod.sch.uk"),
    ("www.sch.uk", "www.sch.uk"),
    ("co.uk", "co.uk"),
    ("www.co.uk", "co.uk"),
    ("blogspot.co.uk", "blogspot.co.uk"), // PRIVATE DOMAIN.
    ("blogspot.nic.uk", "uk"),
    ("blogspot.sch.uk", "blogspot.sch.uk"),
    // The .рф rules are
    // рф (xn--p1ai)
    ("xn--p1ai", "xn--p1ai"),
    ("aaa.xn--p1ai", "xn--p1ai"),
    ("www.xxx.yyy.xn--p1ai", "xn--p1ai"),
    // The .bd rules are:
    // *.bd
    ("bd", "bd"), // The catch-all "*" rule is not in the ICANN DOMAIN section. See footnote (†).
    ("www.bd", "www.bd"),
    ("xxx.www.bd", "www.bd"),
    ("zzz.bd", "zzz.bd"),
    ("www.zzz.bd", "zzz.bd"),
    ("www.xxx.yyy.zzz.bd", "zzz.bd"),
    // The .ck rules are:
    // *.ck
    // !www.ck
    ("ck", "ck"), // The catch-all "*" rule is not in the ICANN DOMAIN section. See footnote (†).
    ("www.ck", "ck"),
    ("xxx.www.ck", "ck"),
    ("zzz.ck", "zzz.ck"),
    ("www.zzz.ck", "zzz.ck"),
    ("www.xxx.yyy.zzz.ck", "zzz.ck"),
    // The .myjino.ru rules (in the PRIVATE DOMAIN section) are:
    // myjino.ru
    // *.hosting.myjino.ru
    // *.landing.myjino.ru
    // *.spectrum.myjino.ru
    // *.vps.myjino.ru
    ("myjino.ru", "myjino.ru"),
    ("aaa.myjino.ru", "myjino.ru"),
    ("bbb.ccc.myjino.ru", "myjino.ru"),
    ("hosting.ddd.myjino.ru", "myjino.ru"),
    ("landing.myjino.ru", "myjino.ru"),
    ("www.landing.myjino.ru", "www.landing.myjino.ru"),
    ("spectrum.vps.myjino.ru", "spectrum.vps.myjino.ru"),
    // The .uberspace.de rules (in the PRIVATE DOMAIN section) are:
    // *.uberspace.de
    ("uberspace.de", "de"), // "de" is in the ICANN DOMAIN section. See footnote (†).
    ("aaa.uberspace.de", "aaa.uberspace.de"),
    ("bbb.ccc.uberspace.de", "ccc.uberspace.de"),
    // There are no .nosuchtld rules.
    ("nosuchtld", "nosuchtld"),
    ("foo.nosuchtld", "nosuchtld"),
    ("bar.foo.nosuchtld", "nosuchtld"),
    // (†) There is some disagreement on how wildcards behave: what should the
    // public suffix of "platform.sh" be when both "*.platform.sh" and "sh" is
    // in the PSL, but "platform.sh" is not? Two possible answers are
    // "platform.sh" and "sh", there are valid arguments for either behavior,
    // and different browsers have implemented different behaviors.
    //
    // This implementation, Go's golang.org/x/net/publicsuffix, returns "sh",
    // the same as a literal interpretation of the "Formal Algorithm" section
    // of https://publicsuffix.org/list/
    //
    // Together, the TestPublicSuffix and TestSlowPublicSuffix tests check that
    // the Go implementation (func PublicSuffix in list.go) and the literal
    // interpretation (func slowPublicSuffix in list_test.go) produce the same
    // (golden) results on every test case in this publicSuffixTestCases slice,
    // including some "platform.sh" style cases.
    //
    // More discussion of "the platform.sh problem" is at:
    //  - https://github.com/publicsuffix/list/issues/694
    //  - https://bugzilla.mozilla.org/show_bug.cgi?id=1124625#c6
    //  - https://wiki.mozilla.org/Public_Suffix_List/platform.sh_Problem
];

#[test]
fn test_public_suffix() {
    for &(domain, want_ps) in TEST_CASES.iter() {
        assert_eq!(
            DEFAULT_PROVIDER.public_suffix(domain),
            want_ps,
            "{domain:?} -> {want_ps:?}"
        );
    }
}

// TODO: PORT TestSlowPublicSuffix

// from
// https://github.com/publicsuffix/list/blob/master/tests/test_psl.txt
static ETLD_PLUS_ONE_TEST_CASES: &[(&str, Result<&'static str, Error>)] = &[
    // Empty input.
    ("", Err(Error::CannotDeriveETldPlus1)),
    // Unlisted TLD.
    ("example", Err(Error::CannotDeriveETldPlus1)),
    ("example.example", Ok("example.example")),
    ("b.example.example", Ok("example.example")),
    ("a.b.example.example", Ok("example.example")),
    // TLD with only 1 rule.
    ("biz", Err(Error::CannotDeriveETldPlus1)),
    ("domain.biz", Ok("domain.biz")),
    ("b.domain.biz", Ok("domain.biz")),
    ("a.b.domain.biz", Ok("domain.biz")),
    // TLD with some 2-level rules.
    ("com", Err(Error::CannotDeriveETldPlus1)),
    ("example.com", Ok("example.com")),
    ("b.example.com", Ok("example.com")),
    ("a.b.example.com", Ok("example.com")),
    ("uk.com", Err(Error::CannotDeriveETldPlus1)),
    ("example.uk.com", Ok("example.uk.com")),
    ("b.example.uk.com", Ok("example.uk.com")),
    ("a.b.example.uk.com", Ok("example.uk.com")),
    ("test.ac", Ok("test.ac")),
    // TLD with only 1 (wildcard) rule.
    ("mm", Err(Error::CannotDeriveETldPlus1)),
    ("c.mm", Err(Error::CannotDeriveETldPlus1)),
    ("b.c.mm", Ok("b.c.mm")),
    ("a.b.c.mm", Ok("b.c.mm")),
    // More complex TLD.
    ("jp", Err(Error::CannotDeriveETldPlus1)),
    ("test.jp", Ok("test.jp")),
    ("www.test.jp", Ok("test.jp")),
    ("ac.jp", Err(Error::CannotDeriveETldPlus1)),
    ("test.ac.jp", Ok("test.ac.jp")),
    ("www.test.ac.jp", Ok("test.ac.jp")),
    ("kyoto.jp", Err(Error::CannotDeriveETldPlus1)),
    ("test.kyoto.jp", Ok("test.kyoto.jp")),
    ("ide.kyoto.jp", Err(Error::CannotDeriveETldPlus1)),
    ("b.ide.kyoto.jp", Ok("b.ide.kyoto.jp")),
    ("a.b.ide.kyoto.jp", Ok("b.ide.kyoto.jp")),
    ("c.kobe.jp", Err(Error::CannotDeriveETldPlus1)),
    ("b.c.kobe.jp", Ok("b.c.kobe.jp")),
    ("a.b.c.kobe.jp", Ok("b.c.kobe.jp")),
    ("city.kobe.jp", Ok("city.kobe.jp")),
    ("www.city.kobe.jp", Ok("city.kobe.jp")),
    // TLD with a wildcard rule and exceptions.
    ("ck", Err(Error::CannotDeriveETldPlus1)),
    ("test.ck", Err(Error::CannotDeriveETldPlus1)),
    ("b.test.ck", Ok("b.test.ck")),
    ("a.b.test.ck", Ok("b.test.ck")),
    ("www.ck", Ok("www.ck")),
    ("www.www.ck", Ok("www.ck")),
    // US K12.
    ("us", Err(Error::CannotDeriveETldPlus1)),
    ("test.us", Ok("test.us")),
    ("www.test.us", Ok("test.us")),
    ("ak.us", Err(Error::CannotDeriveETldPlus1)),
    ("test.ak.us", Ok("test.ak.us")),
    ("www.test.ak.us", Ok("test.ak.us")),
    ("k12.ak.us", Err(Error::CannotDeriveETldPlus1)),
    ("test.k12.ak.us", Ok("test.k12.ak.us")),
    ("www.test.k12.ak.us", Ok("test.k12.ak.us")),
    // Punycoded IDN labels
    ("xn--85x722f.com.cn", Ok("xn--85x722f.com.cn")),
    ("xn--85x722f.xn--55qx5d.cn", Ok("xn--85x722f.xn--55qx5d.cn")),
    (
        "www.xn--85x722f.xn--55qx5d.cn",
        Ok("xn--85x722f.xn--55qx5d.cn"),
    ),
    ("shishi.xn--55qx5d.cn", Ok("shishi.xn--55qx5d.cn")),
    ("xn--55qx5d.cn", Err(Error::CannotDeriveETldPlus1)),
    ("xn--85x722f.xn--fiqs8s", Ok("xn--85x722f.xn--fiqs8s")),
    ("www.xn--85x722f.xn--fiqs8s", Ok("xn--85x722f.xn--fiqs8s")),
    ("shishi.xn--fiqs8s", Ok("shishi.xn--fiqs8s")),
    ("xn--fiqs8s", Err(Error::CannotDeriveETldPlus1)),
    // Invalid input
    (".", Err(Error::EmptyLabel)),
    ("de.", Err(Error::EmptyLabel)),
    (".de", Err(Error::EmptyLabel)),
    (".com.au", Err(Error::EmptyLabel)),
    ("com.au.", Err(Error::EmptyLabel)),
    ("com..au", Err(Error::EmptyLabel)),
];

#[test]
fn effective_tld_plus_one_test() {
    for &(domain, want) in ETLD_PLUS_ONE_TEST_CASES {
        assert_eq!(
            DEFAULT_PROVIDER.effective_tld_plus_one(domain),
            want,
            "{domain:?} -> {want:?}"
        );
    }
}
