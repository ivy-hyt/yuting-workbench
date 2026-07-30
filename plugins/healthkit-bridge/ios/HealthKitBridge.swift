import Foundation
import Capacitor
import HealthKit

/// 桥接 Apple HealthKit：授权 + 读取今日运动健康数据
@objc(HealthKitBridge)
class HealthKitBridge: CAPPlugin {

    private let healthStore = HKHealthStore()

    // MARK: - 是否可用
    @objc func isAvailable(_ call: CAPPluginCall) {
        call.resolve(["available": HKHealthStore.isHealthDataAvailable()])
    }

    // MARK: - 请求授权
    @objc func requestAuthorization(_ call: CAPPluginCall) {
        guard HKHealthStore.isHealthDataAvailable() else {
            call.reject("此设备不支持 HealthKit（需在真机 iPhone 上运行）")
            return
        }

        guard
            let stepType = HKObjectType.quantityType(forIdentifier: .stepCount),
            let energyType = HKObjectType.quantityType(forIdentifier: .activeEnergyBurned),
            let weightType = HKObjectType.quantityType(forIdentifier: .bodyMass),
            let hrType = HKObjectType.quantityType(forIdentifier: .heartRate),
            let sleepType = HKObjectType.categoryType(forIdentifier: .sleepAnalysis)
        else {
            call.reject("无法创建健康数据类型")
            return
        }

        let readTypes: Set<HKObjectType> = [stepType, energyType, weightType, hrType, sleepType]

        healthStore.requestAuthorization(toShare: nil, read: readTypes) { granted, error in
            DispatchQueue.main.async {
                if let error = error {
                    call.reject(error.localizedDescription)
                    return
                }
                call.resolve(["authorized": granted])
            }
        }
    }

    // MARK: - 读取今日数据
    @objc func queryToday(_ call: CAPPluginCall) {
        guard HKHealthStore.isHealthDataAvailable() else {
            call.reject("此设备不支持 HealthKit")
            return
        }

        let calendar = Calendar.current
        let now = Date()
        guard let startOfDay = calendar.date(bySettingHour: 0, minute: 0, second: 0, of: now) else {
            call.reject("日期计算失败")
            return
        }

        let group = DispatchGroup()
        var result: [String: Any] = ["date": Self.dayString(now)]

        // 步数（今日累计）
        group.enter()
        querySum(type: .stepCount, unit: HKUnit.count(), start: startOfDay, end: now) { val, _ in
            if let val = val { result["steps"] = Int(val) }
            group.leave()
        }

        // 活动卡路里（今日累计）
        group.enter()
        querySum(type: .activeEnergyBurned, unit: HKUnit.kilocalorie(), start: startOfDay, end: now) { val, _ in
            if let val = val { result["calories"] = val }
            group.leave()
        }

        // 最新体重
        group.enter()
        queryLatestSample(type: .bodyMass, unit: HKUnit.gramUnit(with: .kilo)) { val, _ in
            if let val = val { result["weight"] = val }
            group.leave()
        }

        // 最新心率
        group.enter()
        queryLatestSample(type: .heartRate, unit: HKUnit.count().unitDivided(by: HKUnit.minute())) { val, _ in
            if let val = val { result["heartRate"] = val }
            group.leave()
        }

        // 今日睡眠时长（小时）
        group.enter()
        querySleepHours(start: startOfDay, end: now) { hours, _ in
            if let hours = hours { result["sleepHours"] = hours }
            group.leave()
        }

        group.notify(queue: .main) {
            call.resolve(result)
        }
    }

    // MARK: - 工具方法
    private func querySum(type: HKQuantityTypeIdentifier, unit: HKUnit, start: Date, end: Date,
                          completion: @escaping (Double?, Error?) -> Void) {
        guard let qType = HKObjectType.quantityType(forIdentifier: type) else {
            completion(nil, nil); return
        }
        let predicate = HKQuery.predicateForSamples(withStart: start, end: end, options: .strictStartDate)
        let query = HKStatisticsQuery(quantityType: qType, quantitySamplePredicate: predicate, options: .cumulativeSum) { _, stats, error in
            if let sum = stats?.sumQuantity() {
                completion(sum.doubleValue(for: unit), nil)
            } else {
                completion(nil, error)
            }
        }
        healthStore.execute(query)
    }

    private func queryLatestSample(type: HKQuantityTypeIdentifier, unit: HKUnit,
                                   completion: @escaping (Double?, Error?) -> Void) {
        guard let qType = HKObjectType.quantityType(forIdentifier: type) else {
            completion(nil, nil); return
        }
        let sort = NSSortDescriptor(key: HKSampleSortIdentifierEndDate, ascending: false)
        let query = HKSampleQuery(sampleType: qType, predicate: nil, limit: 1, sortDescriptors: [sort]) { _, samples, error in
            if let sample = samples?.first as? HKQuantitySample {
                completion(sample.quantity.doubleValue(for: unit), nil)
            } else {
                completion(nil, error)
            }
        }
        healthStore.execute(query)
    }

    private func querySleepHours(start: Date, end: Date, completion: @escaping (Double?, Error?) -> Void) {
        guard let sleepType = HKObjectType.categoryType(forIdentifier: .sleepAnalysis) else {
            completion(nil, nil); return
        }
        let predicate = HKQuery.predicateForSamples(withStart: start, end: end, options: .strictStartDate)
        let query = HKSampleQuery(sampleType: sleepType, predicate: predicate, limit: HKObjectQueryNoLimit, sortDescriptors: nil) { _, samples, error in
            guard let samples = samples as? [HKCategorySample], error == nil else {
                completion(nil, error); return
            }
            var total: TimeInterval = 0
            for s in samples {
                // 只统计睡眠中的状态（asleep 系列）
                if s.value != HKCategoryValueSleepAnalysis.awake.rawValue {
                    total += s.endDate.timeIntervalSince(s.startDate)
                }
            }
            completion(total / 3600.0, nil)
        }
        healthStore.execute(query)
    }

    private static func dayString(_ date: Date) -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyyMMdd"
        return f.string(from: date)
    }
}
